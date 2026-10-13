// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! A scratch directory that removes itself.
//!
//! The integration fixtures used to `create_dir_all` under the temp dir and
//! return a bare `PathBuf`. Nothing removed it, and a panicking test never
//! reached a cleanup line anyway: by 2026-10-02 a dev box held hundreds of
//! `/tmp/noo-cli-*` directories, the sops ones each carrying an age key, a
//! `.sops.yaml`, an encrypted store and a `.env`. Throwaway values, but the
//! shape of a real secrets root, left lying around.
//!
//! [`ScratchDir`] owns the path and removes it in `Drop`, which also runs
//! while a failing test unwinds. It derefs to `PathBuf`, so `root.join(..)`,
//! `&root` as `&Path`/`&PathBuf`, and `.env("HOME", &root)` all keep working.
//!
//! `NOO_KEEP_TEST_DIRS=1` keeps every directory, and prints where each one
//! is, for debugging a fixture by hand.
//!
//! Included by path (`#[path = "common/scratch_dir.rs"] mod scratch_dir;`):
//! a file under `tests/common/` is not a test target of its own.

#![allow(dead_code)]

use std::ffi::OsStr;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

static SEQ: AtomicU32 = AtomicU32::new(0);

pub struct ScratchDir {
    path: PathBuf,
    keep: bool,
}

impl ScratchDir {
    /// A fresh, empty `<temp>/<prefix>-<pid>-<seq>-<nanos>` directory.
    pub fn new(prefix: &str) -> Self {
        let keep = std::env::var("NOO_KEEP_TEST_DIRS").ok().as_deref() == Some("1");
        Self::with_keep(prefix, keep)
    }

    /// [`new`](Self::new) with the keep decision made by the caller, so the
    /// cleanup itself can be tested whatever the environment says.
    pub fn with_keep(prefix: &str, keep: bool) -> Self {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{n}-{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create scratch dir");
        if keep {
            eprintln!("NOO_KEEP_TEST_DIRS: keeping {}", path.display());
        }
        ScratchDir { path, keep }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

impl Deref for ScratchDir {
    type Target = PathBuf;
    fn deref(&self) -> &PathBuf {
        &self.path
    }
}

impl AsRef<Path> for ScratchDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<OsStr> for ScratchDir {
    fn as_ref(&self) -> &OsStr {
        self.path.as_os_str()
    }
}
