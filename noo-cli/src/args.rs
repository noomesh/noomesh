// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! One argument helper and one argument error for native commands.
//!
//! Hand-rolled `while let Some(a) = it.next()` loops each invented their own
//! error (`()`, `String`, `Unhandled`) and most of them threw the reason
//! away: the user saw "did not understand these arguments" and nothing about
//! WHICH argument. `Args` takes flags out of the token list by name; whatever
//! is left is positional, and a leftover `--x` is an error that names it.
//!
//! An `ArgError` converts into [`crate::Unhandled`] with `?`, stashing its
//! message; `main::usage_error` prints that message under the usage line
//! (exit 2, as before).
//!
//! Syntax accepted is exactly what the loops accepted: `--flag value` and
//! short aliases. `--flag=value` is NOT supported (nor was it).
//!
//! Convention for converted parsers: ask for every flag FIRST, positionals
//! last. The tie test (`usage_flags_match_what_converted_parsers_ask_for`)
//! runs each parser on empty input and compares the flags it asked about
//! with the flags `usage.rs` documents for that verb.

use std::sync::Mutex;

/// A user-facing reason an argument list was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgError(pub String);

impl ArgError {
    pub fn new(msg: impl Into<String>) -> Self {
        ArgError(msg.into())
    }
}

impl std::fmt::Display for ArgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for ArgError {
    fn from(s: String) -> Self {
        ArgError(s)
    }
}

static LAST: Mutex<Option<String>> = Mutex::new(None);

impl From<ArgError> for crate::Unhandled {
    fn from(e: ArgError) -> Self {
        if let Ok(mut g) = LAST.lock() {
            *g = Some(e.0);
        }
        crate::Unhandled
    }
}

/// The message of the last `ArgError` turned into `Unhandled`, once.
pub fn take_message() -> Option<String> {
    LAST.lock().ok().and_then(|mut g| g.take())
}

/// Tokens still to be consumed, plus the flags the parser asked about.
pub struct Args {
    rest: Vec<String>,
    asked: Vec<String>,
}

impl Args {
    pub fn new(args: &[String]) -> Self {
        Args { rest: args.to_vec(), asked: Vec::new() }
    }

    /// `names[0]` is the canonical flag (what usage documents); the rest are
    /// aliases.
    fn note(&mut self, names: &[&str]) {
        if let Some(first) = names.first() {
            if !self.asked.iter().any(|a| a == first) {
                self.asked.push((*first).to_string());
            }
        }
    }

    /// Canonical names of every flag asked about so far.
    #[cfg(test)]
    pub fn asked(&self) -> &[String] {
        &self.asked
    }

    /// A switch: present or not.
    pub fn flag(&mut self, names: &[&str]) -> bool {
        self.note(names);
        let before = self.rest.len();
        self.rest.retain(|t| !names.contains(&t.as_str()));
        self.rest.len() != before
    }

    /// `--flag <value>`; the last occurrence wins. A flag with no value
    /// after it is an error.
    pub fn value(&mut self, names: &[&str]) -> Result<Option<String>, ArgError> {
        self.note(names);
        let mut found = None;
        while let Some(i) = self.rest.iter().position(|t| names.contains(&t.as_str())) {
            if i + 1 >= self.rest.len() {
                return Err(ArgError::new(format!("{} needs a value", self.rest[i])));
            }
            let v = self.rest.remove(i + 1);
            self.rest.remove(i);
            found = Some(v);
        }
        Ok(found)
    }

    /// `--flag <number>`; surrounding whitespace is ignored.
    pub fn number<T: std::str::FromStr>(&mut self, names: &[&str]) -> Result<Option<T>, ArgError> {
        match self.value(names)? {
            None => Ok(None),
            Some(v) => match v.trim().parse::<T>() {
                Ok(n) => Ok(Some(n)),
                Err(_) => Err(ArgError::new(format!("{} needs a number, got `{v}`", names[0]))),
            },
        }
    }

    /// Everything left, in order. A leftover `-x` / `--x` is an unknown flag
    /// (a lone `-` is a positional).
    pub fn positionals(&mut self) -> Result<Vec<String>, ArgError> {
        if let Some(t) = self.rest.iter().find(|t| t.len() > 1 && t.starts_with('-')) {
            return Err(ArgError::new(format!("unknown flag `{t}`")));
        }
        Ok(std::mem::take(&mut self.rest))
    }

    /// Exactly one positional (`what` names it in the error).
    pub fn one(&mut self, what: &str) -> Result<String, ArgError> {
        let mut p = self.positionals()?;
        match p.len() {
            1 => Ok(p.remove(0)),
            0 => Err(ArgError::new(format!("missing {what}"))),
            _ => Err(ArgError::new(format!("unexpected argument `{}` after {what}", p[1]))),
        }
    }

    /// Nothing may be left.
    pub fn finish(&mut self) -> Result<(), ArgError> {
        let p = self.positionals()?;
        match p.first() {
            None => Ok(()),
            Some(t) => Err(ArgError::new(format!("unexpected argument `{t}`"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn flags_values_and_positionals() {
        let mut a = Args::new(&s(&["host3", "--force", "--limit", "5", "-n", "7", "--node", "x"]));
        assert!(a.flag(&["--force"]));
        assert!(!a.flag(&["--now"]));
        assert_eq!(a.number::<u64>(&["--limit", "-n"]).unwrap(), Some(7), "last wins, alias taken");
        assert_eq!(a.value(&["--node"]).unwrap().as_deref(), Some("x"));
        assert_eq!(a.value(&["--reason"]).unwrap(), None);
        assert_eq!(a.positionals().unwrap(), s(&["host3"]));
        assert_eq!(a.asked(), s(&["--force", "--now", "--limit", "--node", "--reason"]).as_slice());
    }

    #[test]
    fn a_value_may_look_like_a_flag() {
        let mut a = Args::new(&s(&["--q", "--odd"]));
        assert_eq!(a.value(&["--q"]).unwrap().as_deref(), Some("--odd"));
        a.finish().unwrap();
    }

    #[test]
    fn a_missing_or_bad_value_is_an_error_with_the_flag_name() {
        let e = Args::new(&s(&["--node"])).value(&["--node"]).unwrap_err();
        assert_eq!(e.0, "--node needs a value");
        let e = Args::new(&s(&["--limit", "soon"])).number::<u64>(&["--limit"]).unwrap_err();
        assert!(e.0.contains("--limit") && e.0.contains("soon"), "{e}");
    }

    #[test]
    fn a_leftover_flag_names_itself() {
        let mut a = Args::new(&s(&["--bogus"]));
        assert_eq!(a.positionals().unwrap_err().0, "unknown flag `--bogus`");
        let mut a = Args::new(&s(&["extra"]));
        assert_eq!(a.finish().unwrap_err().0, "unexpected argument `extra`");
        let mut a = Args::new(&s(&["-"]));
        assert_eq!(a.positionals().unwrap(), s(&["-"]));
    }

    #[test]
    fn one_wants_exactly_one() {
        assert_eq!(Args::new(&s(&["a"])).one("<node>").unwrap(), "a");
        assert_eq!(Args::new(&[]).one("<node>").unwrap_err().0, "missing <node>");
        assert!(Args::new(&s(&["a", "b"])).one("<node>").is_err());
        assert!(Args::new(&s(&["a", "--x"])).one("<node>").is_err());
    }

    #[test]
    fn an_arg_error_reaches_usage_error_through_unhandled() {
        fn f() -> Result<(), crate::Unhandled> {
            Err::<(), _>(ArgError::new("--node needs a value"))?;
            Ok(())
        }
        assert!(f().is_err());
        assert_eq!(take_message().as_deref(), Some("--node needs a value"));
        assert_eq!(take_message(), None, "taken once");
    }

    /// `--flag` tokens a usage syntax documents.
    fn usage_flags(words: &[&str]) -> BTreeSet<String> {
        let (syntax, _) = crate::usage::lookup(words).unwrap_or_else(|| panic!("no usage for {words:?}"));
        syntax
            .split_whitespace()
            .flat_map(|t| t.split('|'))
            .map(|t| t.trim_matches(|c: char| c == '[' || c == ']' || c == '.'))
            .filter(|t| t.starts_with("--"))
            .map(str::to_string)
            .collect()
    }

    /// The FLAG half of "usage and parser agree": for each converted verb,
    /// the flags its parser asks about (run on empty input; every flag is
    /// asked before any positional is demanded) equal the flags `usage.rs`
    /// documents. A flag added to one side only fails here. Add a row when
    /// converting another verb.
    #[test]
    fn usage_flags_match_what_converted_parsers_ask_for() {
        use crate::commands::{cluster_gpu, cluster_reserve, cluster_vendor, heartbeat, walks};
        type Probe = fn(&mut Args);
        fn row<'a>(w: &'a [&'a str], p: Probe) -> (&'a [&'a str], Probe) {
            (w, p)
        }
        let table = [
            row(&["heartbeat", "history"], |a| { let _ = heartbeat::parse_history_with(a); }),
            row(&["walks"], |a| { let _ = walks::parse_list_with(a); }),
            row(&["cluster", "reserve"], |a| { let _ = cluster_reserve::parse_reserve_with(a); }),
            row(&["cluster", "gpu", "hold"], |a| { let _ = cluster_gpu::parse_gpu_hold_with(a); }),
            row(&["cluster", "gpu", "release"], |a| { let _ = cluster_gpu::parse_gpu_release_with(a); }),
            row(&["cluster", "vendor", "stage"], |a| { let _ = cluster_vendor::parse_stage_with(a); }),
        ];
        let mut bad = Vec::new();
        for (words, probe) in table {
            let mut a = Args::new(&[]);
            probe(&mut a);
            let parsed: BTreeSet<String> = a.asked().iter().filter(|f| f.starts_with("--")).cloned().collect();
            let documented = usage_flags(words);
            if parsed != documented {
                bad.push(format!(
                    "noo {}: parser-only {:?}, usage-only {:?}",
                    words.join(" "),
                    parsed.difference(&documented).collect::<Vec<_>>(),
                    documented.difference(&parsed).collect::<Vec<_>>()
                ));
            }
        }
        assert!(bad.is_empty(), "usage.rs and the parser disagree:\n  {}", bad.join("\n  "));
    }
}
