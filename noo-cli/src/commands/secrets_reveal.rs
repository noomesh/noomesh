// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo security secrets reveal <NAME>` — hand ONE secret to the human who
//! has to hold it, once, and leave no copy behind.
//!
//! # Why this exists
//!
//! Two of this system's secrets are not consumed by any process on the box:
//! `NOO_BACKUP_PASSPHRASE` and `NOO_AGE_BACKUP_PASSPHRASE` exist so that a
//! PERSON can open a backup on a machine that is not this one. A secret whose
//! only consumer is a human is worthless unless the human can read it.
//!
//! Until now the wizard solved that by writing
//! `secrets/age_backup_passphrase.txt` in the clear and warning the operator
//! to copy it into a password manager. Nothing ever removed the file. The
//! plaintext root-of-trust passphrase therefore sat next to the encrypted
//! store on every controller, indefinitely, because the readable path and the
//! durable path were the same path.
//!
//! This command splits them: the readable path is a TTY, and it is transient.
//!
//! # The gate
//!
//! There is deliberately NO extra credential here. This command reads the
//! LOCAL sops store, so the gate is the local age key — whoever can run
//! `sops -d secrets/env.sops` on this box can already read every secret it
//! holds, by hand, today. Adding an Operator bearer check would be theatre: it
//! would gate a capability the caller demonstrably already has, and it would
//! make the one command you need during a recovery depend on a gateway that
//! may be the thing you are recovering. What this command adds over
//! `sops -d | grep` is the guard rail, not the authorisation: an allow-list,
//! a TTY requirement, and an audit line.
//!
//! # What it refuses
//!
//! * A non-TTY stdout, unless `--stdout` is passed explicitly. A value that
//!   lands in a pipe lands in whatever that pipe writes to — a log, a CI
//!   artifact, a transcript. `--stdout` is how you say "I meant it".
//! * `--json`, always. A JSON stream is a machine surface; machines log.
//! * Any name outside [`ALLOW_LIST`]. The allow-list is the point: this is a
//!   verb for the handful of secrets a human must hold, not a general
//!   `getsecret`.
//! * The age private key itself, with a pointer rather than a flag. See
//!   [`reveal_policy`].

use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::commands::secrets::SecretStore;
use crate::output::{fail, ExitCode};
use crate::ui::{self, Glyph};
use crate::{envfile, Globals, Unhandled};

/// How long a clipboard copy is allowed to live.
pub const CLIPBOARD_TTL_SECS: u64 = 45;

// ─────────────────────────────────────────────────────────────────────────
// The allow-list
// ─────────────────────────────────────────────────────────────────────────

/// Secrets a human is supposed to hold, and the one sentence that says why.
///
/// Both entries are backup passphrases: neither is read by any container, and
/// both are useless on this machine after this machine is gone. That is the
/// membership rule — a secret belongs here when its consumer is a person
/// standing in front of a machine that is NOT this one.
pub const ALLOW_LIST: &[(&str, &str)] = &[
    (
        "NOO_AGE_BACKUP_PASSPHRASE",
        "opens the encrypted age-key backup — the key that opens every other secret",
    ),
    (
        "NOO_BACKUP_PASSPHRASE",
        "opens the encrypted Postgres dumps in the backup directory",
    ),
];

/// Names that denote the age PRIVATE KEY rather than a passphrase.
const AGE_KEY_NAMES: &[&str] = &[
    "SOPS_AGE_KEY",
    "SOPS_AGE_KEY_FILE",
    "NOO_AGE_KEY",
    "AGE_KEY",
    "AGE_PRIVATE_KEY",
];

#[derive(Debug, PartialEq, Eq)]
pub enum Policy {
    /// On the allow-list; reveal it (subject to the TTY guard).
    Allowed,
    /// The age private key. Refused outright — see below.
    AgeKeyRefused,
    /// Anything else.
    NotHumanHeld,
}

/// Decide whether a name may be revealed.
///
/// # Why the age key is refused rather than gated behind `--i-understand`
///
/// The obvious design is a scary flag plus a second confirmation. It was
/// rejected, on two grounds:
///
/// 1. **It buys no recovery capability.** The age key's recovery artifact
///    already exists: `backup-controller.sh` writes an encrypted copy of it,
///    protected by `NOO_AGE_BACKUP_PASSPHRASE` — which IS on the allow-list.
///    The supported way to carry the root of trust off-box is "store the
///    passphrase, keep the encrypted key". Printing the key adds a SECOND
///    off-box copy of the root of trust, in a weaker container (a clipboard,
///    a scrollback buffer, a password-manager note), for no recovery power
///    the first copy lacks.
/// 2. **A human cannot hold it anyway.** It is a multi-line key file, not a
///    string anyone transcribes into a password-manager field. The operation
///    people actually want — "get the key onto the new box" — is a file copy,
///    which `noo migrate export` and the encrypted backup both already do.
///
/// So this returns a refusal that points at the path that works. A flag that
/// exists is a flag that gets used; the value of refusing is that there is no
/// TTY-shaped way to spill the root of trust at all.
pub fn reveal_policy(name: &str) -> Policy {
    let n = name.trim().to_ascii_uppercase();
    if AGE_KEY_NAMES.contains(&n.as_str()) {
        return Policy::AgeKeyRefused;
    }
    match canonical_name(name) {
        Some(_) => Policy::Allowed,
        None => Policy::NotHumanHeld,
    }
}

/// Canonical spelling of an allow-listed name. `reveal age_backup_passphrase`
/// and `reveal NOO_AGE_BACKUP_PASSPHRASE` are the same request: the operator
/// reading a runbook types the env var, the operator remembering the old
/// plaintext file types its stem, and refusing one of them teaches nothing.
pub fn canonical_name(name: &str) -> Option<&'static str> {
    let n = name.trim().to_ascii_uppercase();
    let prefixed = if n.starts_with("NOO_") { n.clone() } else { format!("NOO_{n}") };
    ALLOW_LIST
        .iter()
        .map(|(k, _)| *k)
        .find(|k| **k == *n || **k == *prefixed)
}

// ─────────────────────────────────────────────────────────────────────────
// The TTY guard
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum Guard {
    /// Print it.
    Show,
    /// Refuse, with this reason.
    Refuse(&'static str),
}

/// Where the value is allowed to go. Pure over the two facts that matter so
/// it can be tested without a terminal — the whole point of this command is
/// that it behaves correctly when there is no terminal, and a guard that only
/// runs on a TTY cannot be tested on CI.
///
/// `--stdout` is an explicit override, not an escape hatch with a warning:
/// the caller has said in the argv that a non-terminal destination is
/// intended. `--json` has no override, because there is no case where a
/// machine-readable stream of secret values is what someone meant.
pub fn reveal_guard(stdout_is_tty: bool, stdout_flag: bool, json: bool) -> Guard {
    if json {
        return Guard::Refuse(
            "--json would put the value in a machine-readable stream; there is no --json reveal",
        );
    }
    if stdout_is_tty || stdout_flag {
        return Guard::Show;
    }
    Guard::Refuse(
        "stdout is not a terminal — the value would land in a pipe, a log or a transcript; \
         pass --stdout if that is genuinely what you want",
    )
}

// ─────────────────────────────────────────────────────────────────────────
// The audit line
// ─────────────────────────────────────────────────────────────────────────

/// One line per reveal, appended to `secrets/reveal-audit.log`.
///
/// The name, the time, who asked and where it went — never the value, and
/// never anything from which the value could be recovered. `sha8` is the same
/// derived form `secrets audit` already prints, so an operator can tell "the
/// passphrase I was shown in March" from "the one I was shown in June"
/// without either line containing a passphrase.
pub fn audit_line(when: &str, name: &str, who: &str, sink: &str, sha8: &str) -> String {
    format!("{when} reveal name={name} by={who} sink={sink} sha8={sha8}")
}

fn audit_path(root: &Path) -> PathBuf {
    root.join("secrets").join(REVEAL_AUDIT_LOG)
}

/// The reveal audit log's file name under `secrets/` (names and times, no
/// values). Declared once; verify's residue check allows it by this const.
pub(crate) const REVEAL_AUDIT_LOG: &str = "reveal-audit.log";

/// Append one audit line, 0600. A failure here is reported but does not
/// suppress the reveal: refusing to show the operator their own backup
/// passphrase because a log file was unwritable would turn a bookkeeping
/// problem into a recovery failure.
pub(crate) fn write_audit(root: &Path, line: &str) -> Result<PathBuf, String> {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    let path = audit_path(root);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    writeln!(f, "{line}").map_err(|e| e.to_string())?;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    Ok(path)
}

/// Hand a value the operator has never seen to the operator, once: audit it,
/// print it, and make them say it is stored.
///
/// Split out of `secrets_reveal` on 2026-09-12 so `secrets rotate` can use the
/// same handover for a GENERATED backup passphrase. A generated value that
/// does not reach a human is not a rotation — every artifact re-encrypted to
/// it is simply gone — which makes printing it mandatory, and makes printing
/// it into a pipe the exact accident the guard above exists to stop. Callers
/// must therefore consult [`reveal_guard`] first; this function assumes that
/// verdict was `Show`.
///
/// "Press Enter" is not a confirmation — it is what you do to make a prompt go
/// away — so this asks for a word. Without a terminal on stdin it cannot ask,
/// and returns Ok: the value has still been printed to the destination the
/// caller was told was acceptable (`--stdout`).
///
/// Errors mean ABORT: the operator typed `abort`, and the caller must change
/// nothing.
pub fn hand_to_operator(root: &Path, name: &str, value: &str) -> Result<(), String> {
    // Audit BEFORE printing, so the log over-reports rather than
    // under-reports: a crash between the two should leave evidence that the
    // value may have been seen, not evidence that it was not.
    let line = audit_line(
        &now_rfc3339(),
        name,
        &whoami(),
        if std::io::stdout().is_terminal() { "tty" } else { "stdout" },
        &crate::commands::secrets::sha8_of(value),
    );
    if let Err(e) = write_audit(root, &line) {
        // Not fatal — see write_audit's own note. Say so rather than
        // pretending the handover is unlogged.
        eprintln!("{}", ui::note(&format!("could not append to the reveal audit log: {e}")));
    }
    println!();
    println!("{}", ui::warn(&format!("New {name} — shown once, written to no file:")));
    println!("    {value}");
    println!();
    if unsafe { libc::isatty(0) } == 1 {
        use std::io::{BufRead as _, Write as _};
        loop {
            eprint!("  Type 'stored' once it is in your password manager (or 'abort'): ");
            let _ = std::io::stderr().flush();
            let mut ans = String::new();
            if std::io::stdin().lock().read_line(&mut ans).is_err() {
                return Err(format!("could not read the confirmation for {name}"));
            }
            match ans.trim() {
                "stored" => return Ok(()),
                "abort" => return Err(format!("aborted at the {name} handover")),
                // EOF: read_line returns 0 bytes forever. Treat it as abort
                // rather than spinning.
                "" if ans.is_empty() => return Err(format!("stdin closed at the {name} handover")),
                _ => {}
            }
        }
    }
    Ok(())
}

/// A soft yes/no. Unlike `commands::confirm_destructive` this does NOT abort
/// the command on "no" — the reveal has already succeeded by the time it is
/// asked, and killing the process over a declined cleanup would make the
/// operator run the reveal twice.
fn ask_yn(prompt: &str) -> bool {
    use std::io::{BufRead as _, Write as _};
    if unsafe { libc::isatty(0) } != 1 {
        return false;
    }
    eprint!("{prompt} [y/N]: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

pub(crate) fn now_rfc3339() -> String {
    let out = Command::new("date").args(["-u", "+%Y-%m-%dT%H:%M:%SZ"]).output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => "unknown-time".to_string(),
    }
}

pub(crate) fn whoami() -> String {
    std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

// ─────────────────────────────────────────────────────────────────────────
// Clipboard
// ─────────────────────────────────────────────────────────────────────────

/// A clipboard program, how to feed it, and whether it can be cleared again.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ClipTool {
    /// argv that reads the value on stdin. The value NEVER appears in argv —
    /// argv is world-readable in `/proc`.
    pub copy: &'static [&'static str],
    /// argv that empties the clipboard, when the platform allows it.
    /// `None` means "this tool cannot un-copy", which is said out loud.
    pub clear: Option<&'static [&'static str]>,
    pub label: &'static str,
}

/// Pick a clipboard tool, in the order that matches how the box is being
/// used. Pure over a `which`-shaped probe so the selection can be tested on a
/// CI box with no clipboard at all.
///
/// WSL is checked BEFORE the X11 tools: a WSL2 box frequently has `xclip`
/// installed with no X server behind it, so `xclip` would "succeed" into a
/// clipboard nobody can paste from — the operator would believe the
/// passphrase was copied and it would not be. `clip.exe` reaches the Windows
/// clipboard the operator's password manager is actually on.
pub fn clip_tool(is_wsl: bool, has: impl Fn(&str) -> bool) -> Option<ClipTool> {
    if is_wsl && has("clip.exe") {
        // Windows has no supported "empty the clipboard" CLI, and writing a
        // single space would leave a clipboard entry that LOOKS cleared while
        // the password manager may still hold history. Say so instead.
        return Some(ClipTool { copy: &["clip.exe"], clear: None, label: "clip.exe" });
    }
    if has("wl-copy") {
        return Some(ClipTool {
            copy: &["wl-copy"],
            clear: Some(&["wl-copy", "--clear"]),
            label: "wl-copy",
        });
    }
    if has("pbcopy") {
        return Some(ClipTool { copy: &["pbcopy"], clear: Some(&["pbcopy"]), label: "pbcopy" });
    }
    if has("xclip") {
        return Some(ClipTool {
            copy: &["xclip", "-selection", "clipboard"],
            clear: Some(&["xclip", "-selection", "clipboard"]),
            label: "xclip",
        });
    }
    None
}

fn is_wsl() -> bool {
    std::fs::read_to_string("/proc/version")
        .map(|v| v.to_ascii_lowercase().contains("microsoft"))
        .unwrap_or(false)
}

/// Feed the value to the tool on stdin. Returns whether it was accepted.
fn clip_copy(tool: &ClipTool, value: &str) -> bool {
    let Some((prog, rest)) = tool.copy.split_first() else {
        return false;
    };
    let child = Command::new(prog)
        .args(rest)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else { return false };
    if let Some(stdin) = child.stdin.as_mut() {
        if crate::child_stdin::write_child_stdin(stdin, value.as_bytes()).is_err() {
            return false;
        }
    }
    drop(child.stdin.take());
    child.wait().map(|s| s.success()).unwrap_or(false)
}

/// Arm a detached "clear the clipboard in N seconds" child.
///
/// The child's argv contains the CLEAR command only — never the value — so a
/// process listing during those 45 seconds shows `wl-copy --clear`, not a
/// passphrase. It is detached on purpose: the CLI returns immediately, and
/// the clipboard is still emptied if the operator closes the terminal.
fn arm_clipboard_clear(tool: &ClipTool, secs: u64) -> bool {
    let Some(clear) = tool.clear else { return false };
    let argv = clear
        .iter()
        .map(|a| format!("'{}'", a.replace('\'', r"'\''")))
        .collect::<Vec<_>>()
        .join(" ");
    // `wl-copy --clear` takes no stdin; `pbcopy`/`xclip` clear by being fed
    // nothing. Redirecting /dev/null satisfies both shapes.
    let script = format!("sleep {secs}; {argv} </dev/null >/dev/null 2>&1");
    Command::new("sh")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .is_ok()
}

// ─────────────────────────────────────────────────────────────────────────
// Lingering plaintext
// ─────────────────────────────────────────────────────────────────────────

/// The plaintext files onboard used to leave behind, relative to the repo
/// root. `security scan` reports any that still exist as CRITICAL, and the
/// reveal offers to shred the one it just showed you.
pub const PLAINTEXT_PASSPHRASE_FILES: &[(&str, &str)] = &[
    ("NOO_AGE_BACKUP_PASSPHRASE", "secrets/age_backup_passphrase.txt"),
    ("NOO_BACKUP_PASSPHRASE", "secrets/backup_passphrase.txt"),
];

/// The bcrypt hash of the admin password. Not a credential in itself, but
/// a file nothing reads and an offline crack target; `absorb-files` shreds
/// it once the password it hashes is confirmed in the store.
pub const ADMIN_HASH_FILE: &str = "secrets/admin_password.txt";

/// EVERY plaintext file an older `noo onboard` left in `secrets/`: the two
/// passphrases above, plus the sixteen credentials it wrote on every install
/// until an earlier release (the store was always the value's home; the files only
/// told the wizard it had already run). `security scan` reports each as
/// CRITICAL, `noo onboard` offers to shred them, and
/// `noo security secrets absorb-files` folds each into the store and shreds
/// it once the round-trip is verified.
pub const LEGACY_PLAINTEXT_FILES: &[(&str, &str)] = &[
    ("NOO_AGE_BACKUP_PASSPHRASE", "secrets/age_backup_passphrase.txt"),
    ("NOO_BACKUP_PASSPHRASE", "secrets/backup_passphrase.txt"),
    ("NOO_JWT_SECRET", "secrets/jwt_secret.txt"),
    ("NOO_AGENT_REVIEW_KEY", "secrets/agent_review_key.txt"),
    ("NOO_CONTROLLER_SECRET", "secrets/controller_secret.txt"),
    ("NOO_CLUSTER_SECRET", "secrets/cluster_secret.txt"),
    ("REDIS_PASSWORD", "secrets/redis_password.txt"),
    ("NATS_PASSWORD", "secrets/nats_password.txt"),
    ("NOO_NODE_AGENT_TOKEN", "secrets/node_agent_token.txt"),
    ("POSTGRES_PASSWORD", "secrets/postgres_password.txt"),
    ("NOO_MCP_TOKEN", "secrets/mcp_token.txt"),
    ("NATS_GATEWAY_PASSWORD", "secrets/nats_gateway_password.txt"),
    ("NATS_WORKER_PASSWORD", "secrets/nats_worker_password.txt"),
    ("NOO_APP_DB_PASSWORD", "secrets/noo_app_db_password.txt"),
    ("NOO_TRELLION_DB_PASSWORD", "secrets/noo_trellion_db_password.txt"),
    ("NOO_TRELLION_DDL_PASSWORD", "secrets/noo_trellion_ddl_password.txt"),
    ("NOO_EVOLVE_DB_PASSWORD", "secrets/noo_evolve_db_password.txt"),
    ("NOO_ADMIN_PASSWORD", ADMIN_HASH_FILE),
];

/// Which of those files exist right now, given an "does this path exist"
/// probe. Pure so the scan finding can be tested without a filesystem.
pub fn lingering_plaintext(exists: impl Fn(&str) -> bool) -> Vec<&'static str> {
    LEGACY_PLAINTEXT_FILES
        .iter()
        .map(|(_, p)| *p)
        .filter(|p| exists(p))
        .collect()
}

/// Overwrite then unlink. `shred` when it exists (the repo's own
/// absorb-files script learned the hard way that a plain `rm` on this class
/// of file is a claim, not an erasure — tracker note in
/// `scripts/noo-secrets-absorb-files.sh`); a best-effort overwrite otherwise.
pub fn shred_file(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    if crate::host_exec::which("shred").is_some() {
        let ok = Command::new("shred")
            .arg("-u")
            .arg(path)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Ok(());
        }
    }
    // Fallback: overwrite in place, then unlink. Not as good as shred on a
    // journalling filesystem, and the caller is told so.
    if let Ok(md) = std::fs::metadata(path) {
        let zeros = vec![0u8; md.len() as usize];
        let _ = std::fs::write(path, &zeros);
    }
    std::fs::remove_file(path).map_err(|e| e.to_string())
}

// ─────────────────────────────────────────────────────────────────────────
// noo security secrets reveal
// ─────────────────────────────────────────────────────────────────────────

pub fn secrets_reveal(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut name: Option<String> = None;
    let mut no_clipboard = false;
    let mut stdout_flag = false;
    let mut sops_path: Option<PathBuf> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--no-clipboard" => no_clipboard = true,
            "--stdout" => stdout_flag = true,
            "--sops-file" => sops_path = Some(PathBuf::from(iter.next().ok_or(Unhandled)?)),
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if name.is_some() {
                    return Err(Unhandled);
                }
                name = Some(t.to_string());
            }
        }
    }
    let Some(requested) = name else { return Err(Unhandled) };

    // 1. Allow-list, before anything is read. A refusal must not depend on
    //    whether the store happens to hold the key: `reveal NOO_JWT_SECRET`
    //    is refused on a box where that secret exists and on one where it
    //    does not, identically, so the refusal leaks nothing either.
    match reveal_policy(&requested) {
        Policy::AgeKeyRefused => fail(
            g.json,
            ExitCode::Generic,
            "reveal_refused",
            "the age private key is the root of trust and is never printed",
            Some(
                "it is not a string a person holds. Carry it off-box the supported way: the \
                 encrypted age-key backup written by scripts/backup-controller.sh, opened with \
                 NOO_AGE_BACKUP_PASSPHRASE — which this command WILL reveal. See \
                 docs/operating/runbooks/backup-restore-secrets.md",
            ),
        ),
        Policy::NotHumanHeld => fail(
            g.json,
            ExitCode::Generic,
            "reveal_not_allowed",
            &format!("{requested} is not a secret a human is meant to hold"),
            Some(&format!(
                "reveal only shows: {}. Everything else is consumed by a process on this box; \
                 use 'noo security secrets audit' to see its state without its value",
                ALLOW_LIST.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(", ")
            )),
        ),
        Policy::Allowed => {}
    }
    let key = canonical_name(&requested).expect("allow-listed name canonicalises");

    // 2. The destination guard, before the value is read into memory.
    if let Guard::Refuse(why) = reveal_guard(std::io::stdout().is_terminal(), stdout_flag, g.json) {
        fail(
            g.json,
            ExitCode::Generic,
            "reveal_refused",
            why,
            Some("run it from a terminal you are sitting at, on the controller itself"),
        );
    }

    // 3. Read it. env.sops first (the live store); .env second, because
    //    during onboard the value exists in .env for the moments before the
    //    store is encrypted, and a recovery is exactly when you cannot
    //    afford "it is in the other file".
    let root = envfile::repo_root();
    let sops_path = sops_path.unwrap_or_else(|| root.join("secrets/env.sops"));
    let store = match SecretStore::load_sops(&sops_path) {
        Ok(s) => s,
        Err(e) => fail(
            g.json,
            ExitCode::Generic,
            "sops_decrypt_failed",
            &e,
            Some("reveal reads the local store, so the local age key IS the gate"),
        ),
    };
    let value = store
        .value_for_operator_reveal(key)
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            SecretStore::load_env(&root.join(".env"))
                .value_for_operator_reveal(key)
                .filter(|v| !v.trim().is_empty())
        });
    let Some(value) = value else {
        fail(
            g.json,
            ExitCode::Generic,
            "secret_not_set",
            &format!("{key} is not set in {} or .env", sops_path.display()),
            Some("run 'noo onboard' to mint it, or scripts/noo-backup-rotate-passphrase.sh"),
        )
    };

    // 4. Audit BEFORE printing. If the process dies between the two, the log
    //    over-reports a reveal that did not happen — which is the harmless
    //    direction. The other order under-reports one that did.
    let sink = if std::io::stdout().is_terminal() { "tty" } else { "stdout" };
    let line = audit_line(
        &now_rfc3339(),
        key,
        &whoami(),
        sink,
        &crate::commands::secrets::sha8_of(&value),
    );
    let audit_note = match write_audit(&root, &line) {
        Ok(p) => format!("recorded in {}", p.display()),
        Err(e) => format!("NOT recorded ({e}) — the reveal still happened"),
    };

    // 5. Show it.
    let why = ALLOW_LIST.iter().find(|(k, _)| *k == key).map(|(_, w)| *w).unwrap_or("");
    println!("{}", ui::header("reveal", Some(key)));
    println!("{}", ui::note(why));
    println!();
    ui::value(&value);
    println!();

    // 6. Clipboard.
    let mut clip_msg = String::new();
    if !no_clipboard {
        match clip_tool(is_wsl(), |bin| crate::host_exec::which(bin).is_some()) {
            Some(tool) if clip_copy(&tool, &value) => {
                if arm_clipboard_clear(&tool, CLIPBOARD_TTL_SECS) {
                    clip_msg = format!(
                        "copied to the clipboard via {} — cleared in {CLIPBOARD_TTL_SECS}s",
                        tool.label
                    );
                } else {
                    clip_msg = format!(
                        "copied to the clipboard via {} — this platform cannot clear it again; \
                         copy something else when you are done",
                        tool.label
                    );
                }
            }
            Some(tool) => clip_msg = format!("{} failed; the value is above only", tool.label),
            None => {
                clip_msg =
                    "no clipboard tool found (wl-copy, xclip, pbcopy, clip.exe) — the value is \
                     above only"
                        .to_string()
            }
        }
    }
    if !clip_msg.is_empty() {
        println!("{}", ui::status_line(Glyph::Ok, &clip_msg));
    }
    println!("{}", ui::status_line(Glyph::Bullet, &audit_note));

    // 7. Offer to shred the plaintext file this value used to be written to.
    //    This is the whole reason the command exists: the operator has now
    //    read the value, so the file has no remaining job.
    if let Some((_, rel)) = PLAINTEXT_PASSPHRASE_FILES.iter().find(|(k, _)| *k == key) {
        let path = root.join(rel);
        if path.exists() {
            println!();
            println!(
                "{}",
                ui::warn(&format!(
                    "{rel} still holds this value in plaintext on this box"
                ))
            );
            if ask_yn(&format!("shred {rel} now (you have just read the value)")) {
                match shred_file(&path) {
                    Ok(()) => println!("{}", ui::status_line(Glyph::Ok, &format!("{rel} shredded"))),
                    Err(e) => println!(
                        "{}",
                        ui::status_line(Glyph::Err, &format!("could not shred {rel}: {e}"))
                    ),
                }
            } else {
                ui::guide(&[(
                    "noo security scan",
                    "reports the lingering plaintext file as CRITICAL until it is gone",
                )]);
            }
        }
    }

    ui::guide(&[(
        "docs/operating/runbooks/backup-restore-secrets.md",
        "where this passphrase is used and what it opens",
    )]);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list_is_the_two_backup_passphrases() {
        let names: Vec<&str> = ALLOW_LIST.iter().map(|(k, _)| *k).collect();
        assert_eq!(names, vec!["NOO_AGE_BACKUP_PASSPHRASE", "NOO_BACKUP_PASSPHRASE"]);
    }

    #[test]
    fn policy_allows_only_the_allow_list() {
        assert_eq!(reveal_policy("NOO_BACKUP_PASSPHRASE"), Policy::Allowed);
        assert_eq!(reveal_policy("noo_age_backup_passphrase"), Policy::Allowed);
        // A real, high-value secret that is NOT human-held.
        assert_eq!(reveal_policy("NOO_JWT_SECRET"), Policy::NotHumanHeld);
        assert_eq!(reveal_policy("NOO_CLUSTER_SECRET"), Policy::NotHumanHeld);
        assert_eq!(reveal_policy("NOO_ADMIN_PASSWORD"), Policy::NotHumanHeld);
    }

    #[test]
    fn the_age_key_is_refused_with_a_pointer_not_a_flag() {
        for n in ["SOPS_AGE_KEY", "SOPS_AGE_KEY_FILE", "noo_age_key", "AGE_PRIVATE_KEY"] {
            assert_eq!(reveal_policy(n), Policy::AgeKeyRefused, "{n}");
        }
        // And there is no argv that turns the refusal into a reveal. Asserted
        // against this file's own source, because what is being promised is
        // the ABSENCE of an escape hatch, and an absence is exactly what a
        // behavioural test cannot observe: an `--i-understand` arm added
        // later would pass every other test in this module. The needles are
        // QUOTED flag literals, so the prose above (which names the flag it
        // rejected, on purpose) does not trip it.
        let src = include_str!("secrets_reveal.rs");
        for flag in ["\"--i-understand\"", "\"--force\"", "\"--allow-age-key\""] {
            assert!(!src.contains(flag), "an age-key override arm appeared: {flag}");
        }
    }

    #[test]
    fn guard_refuses_a_pipe_and_json_but_allows_an_explicit_stdout() {
        assert_eq!(reveal_guard(true, false, false), Guard::Show);
        assert!(matches!(reveal_guard(false, false, false), Guard::Refuse(_)));
        assert_eq!(reveal_guard(false, true, false), Guard::Show);
        // --json has no override at all.
        assert!(matches!(reveal_guard(true, true, true), Guard::Refuse(_)));
        assert!(matches!(reveal_guard(true, false, true), Guard::Refuse(_)));
    }

    #[test]
    fn audit_line_never_contains_the_value() {
        let secret = "s3cr3t-passphrase-value";
        let line = audit_line(
            "2026-09-11T10:00:00Z",
            "NOO_BACKUP_PASSPHRASE",
            "operator",
            "tty",
            &crate::commands::secrets::sha8_of(secret),
        );
        assert!(!line.contains(secret), "audit line leaked the value: {line}");
        assert!(line.contains("NOO_BACKUP_PASSPHRASE"));
        assert!(line.contains("2026-09-11T10:00:00Z"));
        assert!(line.contains("by=operator"));
    }

    #[test]
    fn wsl_prefers_clip_exe_over_a_stranded_xclip() {
        let have_both = |t: &str| matches!(t, "xclip" | "clip.exe");
        let t = clip_tool(true, have_both).unwrap();
        assert_eq!(t.label, "clip.exe");
        assert!(t.clear.is_none(), "clip.exe must admit it cannot clear");
        // Off WSL the same box picks xclip.
        let t = clip_tool(false, have_both).unwrap();
        assert_eq!(t.label, "xclip");
        assert!(t.clear.is_some());
    }

    #[test]
    fn no_clipboard_tool_is_none_not_a_silent_noop() {
        assert_eq!(clip_tool(false, |_| false), None);
        assert_eq!(clip_tool(true, |_| false), None);
    }

    #[test]
    fn clipboard_argv_never_carries_the_value() {
        for wsl in [true, false] {
            if let Some(t) = clip_tool(wsl, |_| true) {
                assert!(t.copy.len() <= 3);
                assert!(t.copy.iter().all(|a| !a.contains("passphrase")));
            }
        }
    }

    #[test]
    fn lingering_plaintext_reports_what_exists() {
        assert_eq!(lingering_plaintext(|_| false), Vec::<&str>::new());
        assert_eq!(
            lingering_plaintext(|p| p == "secrets/age_backup_passphrase.txt"),
            vec!["secrets/age_backup_passphrase.txt"]
        );
        assert_eq!(lingering_plaintext(|_| true).len(), LEGACY_PLAINTEXT_FILES.len());
        assert_eq!(
            lingering_plaintext(|p| p == "secrets/cluster_secret.txt"),
            vec!["secrets/cluster_secret.txt"]
        );
    }
}
