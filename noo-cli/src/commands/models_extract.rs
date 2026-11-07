// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The controller-side archive extractor of `noo models stage --extract`
//! (i300 F2b): the bytes of a voice pack arrive as ONE archive from the
//! authenticated Hugging Face fetch, and the controller turns it into flat,
//! individually hashed files. A node never opens an archive.
//!
//! There is no `tar` crate in noo-cli's dependency tree and none is added:
//! the reader below is a small ustar parser over `flate2` (already a
//! dependency). It is deliberately strict and refuses, with a stated reason,
//! everything it does not understand:
//!
//! - only a regular file (typeflag `0` or NUL) is extracted. A symlink, a hard
//!   link, a device, a FIFO, a sparse entry, a GNU long-name or long-link
//!   record and a pax header are each refused;
//! - a directory entry (typeflag `5`, as `tar` writes for `voices/`) is
//!   skipped: nothing is created for it and its mode and owner are never
//!   applied. It still counts toward the entry cap, passes the name checks
//!   (one trailing `/` stripped) and must have size 0. Names are kept as the
//!   archive spells them, so `voices/NATM2.pt` is the set path `voices/NATM2.pt`;
//! - both the POSIX (`ustar\0`) and the old GNU (`ustar  \0`) magic are read;
//! - a member the glob does not select is not written, but it counts toward
//!   the entry and byte caps and passes the same type and name checks;
//! - a name that is absolute, has a `..` component, or changes under
//!   normalisation (`./a`, `a//b`, `a/`) is refused, and so is a duplicate
//!   (also one that differs only in ASCII case);
//! - a SELECTED member's name must pass the model-set path rule
//!   ([`model_set::valid_set_path`]);
//! - decompressed bytes are counted AS THEY ARE READ, never trusted from a
//!   header: one member may not pass [`MAX_MEMBER_BYTES`], the whole stream
//!   (headers and padding included) may not pass [`MAX_TOTAL_BYTES`], and the
//!   archive may not hold more than [`MAX_MEMBERS`] entries.
//!
//! [`extract`] writes into a directory the caller owns; the caller removes
//! that directory on any refusal and renames the files into the set only
//! after every member has passed.

use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::rc::Rc;

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};

use crate::model_set;

/// The most decompressed bytes one member may have.
pub(crate) const MAX_MEMBER_BYTES: u64 = 32 << 20;
/// The most decompressed bytes the whole archive stream may have.
pub(crate) const MAX_TOTAL_BYTES: u64 = 128 << 20;
/// The most entries an archive may hold.
pub(crate) const MAX_MEMBERS: usize = 64;

/// The caps of one extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    pub member_bytes: u64,
    pub total_bytes: u64,
    pub members: usize,
}

impl Limits {
    pub(crate) const DEFAULT: Limits = Limits {
        member_bytes: MAX_MEMBER_BYTES,
        total_bytes: MAX_TOTAL_BYTES,
        members: MAX_MEMBERS,
    };
}

/// One extracted file: its set path, size and sha256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Member {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

/// Counts every byte that comes out of the (decompressed) stream.
struct Counted {
    inner: Box<dyn Read>,
    seen: Rc<Cell<u64>>,
    limit: u64,
}

impl Read for Counted {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        let total = self.seen.get().saturating_add(n as u64);
        self.seen.set(total);
        if !mutant_off() &&total > self.limit {
            return Err(io::Error::other("total cap"));
        }
        Ok(n)
    }
}

struct Stream {
    r: Counted,
    seen: Rc<Cell<u64>>,
    lim: Limits,
}

impl Stream {
    /// A read error as a sentence; the total cap is told apart by the count,
    /// not by the error text, so a decoder that rewraps the error still gets it.
    fn fail(&self, e: &io::Error) -> String {
        if self.seen.get() > self.lim.total_bytes {
            format!(
                "the archive decompresses to more than {} bytes in all (the total cap)",
                self.lim.total_bytes
            )
        } else {
            format!("reading the archive: {e}")
        }
    }

    fn read_some(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        loop {
            match self.r.read(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(self.fail(&e)),
            }
        }
    }

    /// The next 512-byte header block, or None at a clean end of the stream.
    fn header(&mut self) -> Result<Option<[u8; 512]>, String> {
        let mut buf = [0u8; 512];
        let mut got = 0;
        while got < buf.len() {
            let n = self.read_some(&mut buf[got..])?;
            if n == 0 {
                break;
            }
            got += n;
        }
        match got {
            0 => Ok(None),
            512 => Ok(Some(buf)),
            _ => Ok(Some(buf)),
        }
    }

    /// Read `size` bytes of one member, counting them as they come. The
    /// member cap is checked on the bytes actually read. With a `dest`, the
    /// bytes are written to it; either way they are hashed.
    fn member(
        &mut self,
        size: u64,
        mut dest: Option<&mut File>,
        name: &str,
    ) -> Result<(u64, String), String> {
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut done: u64 = 0;
        while done < size {
            let want = (size - done).min(buf.len() as u64) as usize;
            let n = self.read_some(&mut buf[..want])?;
            if n == 0 {
                break;
            }
            done += n as u64;
            if !mutant_off() &&done > self.lim.member_bytes {
                return Err(format!(
                    "member {name:?} decompresses to more than {} bytes (the per-member cap)",
                    self.lim.member_bytes
                ));
            }
            hasher.update(&buf[..n]);
            if let Some(f) = dest.as_mut() {
                f.write_all(&buf[..n]).map_err(|e| format!("writing {name:?}: {e}"))?;
            }
        }
        Ok((done, hex::encode(hasher.finalize())))
    }

    fn skip_padding(&mut self, size: u64) -> Result<(), String> {
        let pad = (512 - size % 512) % 512;
        let mut buf = [0u8; 512];
        let mut left = pad as usize;
        while left > 0 {
            let n = self.read_some(&mut buf[..left])?;
            if n == 0 {
                break;
            }
            left -= n;
        }
        Ok(())
    }
}

fn cstr(field: &[u8]) -> &[u8] {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    &field[..end]
}

/// An octal header field. A base-256 field (high bit set) is refused: it is
/// how GNU tar writes a size past 8 GiB, far past every cap here.
fn octal(field: &[u8]) -> Option<u64> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        return None;
    }
    let text = std::str::from_utf8(cstr(field)).ok()?.trim_matches(' ');
    if text.is_empty() {
        return None;
    }
    u64::from_str_radix(text, 8).ok()
}

fn checksum_ok(h: &[u8; 512]) -> bool {
    let Some(stored) = octal(&h[148..156]) else { return false };
    let sum: u64 = h
        .iter()
        .enumerate()
        .map(|(i, b)| if (148..156).contains(&i) { 32 } else { u64::from(*b) })
        .sum();
    stored == sum
}

fn kind_name(t: u8) -> &'static str {
    match t {
        b'1' => "a hard link",
        b'2' => "a symlink",
        b'3' => "a character device",
        b'4' => "a block device",
        b'5' => "a directory",
        b'6' => "a FIFO",
        b'L' | b'K' => "a GNU long name or long link record",
        b'S' => "a sparse file",
        b'x' | b'g' | b'X' => "a pax extended header",
        _ => "an entry of a type this extractor does not take",
    }
}

fn entry_name(h: &[u8; 512]) -> Result<String, String> {
    let name = cstr(&h[0..100]);
    let posix = !mutant_off() && h[257..263] == b"ustar\0"[..];
    let prefix: &[u8] = if posix { cstr(&h[345..500]) } else { &[] };
    let mut full: Vec<u8> = Vec::new();
    if !prefix.is_empty() {
        full.extend_from_slice(prefix);
        full.push(b'/');
    }
    full.extend_from_slice(name);
    Ok(String::from_utf8_lossy(&full).into_owned())
}

/// The path-safety checks every entry passes, selected or not.
fn check_name(name: &str) -> Result<(), String> {
    if !mutant_off() && name.is_empty() {
        return Err("a member has an empty name".to_string());
    }
    if !mutant_off() &&name.starts_with('/') {
        return Err(format!("member {name:?} is an absolute path"));
    }
    if !mutant_off() &&name.split('/').any(|c| c == "..") {
        return Err(format!("member {name:?} has a `..` component"));
    }
    let normal: Vec<&str> = name.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
    if !mutant_off() &&normal.join("/") != name {
        return Err(format!("member {name:?} changes under normalisation"));
    }
    Ok(())
}

/// `*` and `?` match within one path component; everything else is literal.
pub(crate) fn glob_match(pattern: &str, name: &str) -> bool {
    let p = pattern.as_bytes();
    let n = name.as_bytes();
    let mut prev = vec![false; n.len() + 1];
    prev[0] = true;
    for &pc in p {
        let mut cur = vec![false; n.len() + 1];
        if pc == b'*' {
            cur[0] = prev[0];
        }
        let mut j = 1;
        while j <= n.len() {
            cur[j] = match pc {
                b'*' => prev[j] || (cur[j - 1] && n[j - 1] != b'/'),
                b'?' => prev[j - 1] && n[j - 1] != b'/',
                c => prev[j - 1] && n[j - 1] == c,
            };
            j += 1;
        }
        prev = cur;
    }
    prev[n.len()]
}

fn open_stream(archive: &Path, lim: &Limits) -> Result<Stream, String> {
    let mut f = File::open(archive).map_err(|e| format!("opening the archive: {e}"))?;
    let mut magic = [0u8; 2];
    f.read_exact(&mut magic).map_err(|e| format!("reading the archive: {e}"))?;
    f.seek(SeekFrom::Start(0)).map_err(|e| format!("reading the archive: {e}"))?;
    let inner: Box<dyn Read> =
        if magic == [0x1f, 0x8b] { Box::new(GzDecoder::new(f)) } else { Box::new(f) };
    let seen = Rc::new(Cell::new(0u64));
    let r = Counted { inner, seen: Rc::clone(&seen), limit: lim.total_bytes };
    Ok(Stream { r, seen, lim: *lim })
}

/// Extract the regular files of the gzip-compressed (or plain) tar `archive`
/// whose names match `glob` (all of them without one) into `out`, which is
/// created. Directory entries are skipped. Every refusal is a sentence. Files
/// are written 0644, new, never over anything. On `Err` the caller discards
/// `out`.
pub(crate) fn extract(
    archive: &Path,
    glob: Option<&str>,
    out: &Path,
    lim: &Limits,
) -> Result<Vec<Member>, String> {
    let mut stream = open_stream(archive, lim)?;
    std::fs::create_dir_all(out).map_err(|e| format!("creating {}: {e}", out.display()))?;
    let mut names: Vec<String> = Vec::new();
    let mut members: Vec<Member> = Vec::new();
    let mut entries = 0usize;
    while let Some(h) = stream.header()? {
        if h.iter().all(|b| *b == 0) {
            break;
        }
        entries += 1;
        if !mutant_off() &&entries > lim.members {
            return Err(format!("the archive holds more than {} entries", lim.members));
        }
        if !checksum_ok(&h) {
            return Err("an archive header has a bad checksum (not a tar archive?)".to_string());
        }
        let name = entry_name(&h)?;
        if h[156] == b'5' {
            // A directory entry: it passes the same name checks (less one
            // trailing `/`), is never created, and its mode and owner are
            // never applied. A file under it makes its own directory.
            check_name(name.strip_suffix('/').unwrap_or(&name))?;
            if !mutant_off() &&octal(&h[124..136]) != Some(0) {
                return Err(format!("directory entry {name:?} has a size: it must be empty"));
            }
            continue;
        }
        if !mutant_off() &&h[156] != b'0' && h[156] != 0 {
            let what = kind_name(h[156]);
            return Err(format!("member {name:?} is {what}: only regular files are extracted"));
        }
        check_name(&name)?;
        if !mutant_off() &&names.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
            return Err(format!("member {name:?} appears twice"));
        }
        names.push(name.clone());
        let size = octal(&h[124..136]).unwrap_or(0);
        let selected = glob.is_none_or(|g| glob_match(g, &name));
        if selected {
            if !model_set::valid_set_path(&name) {
                return Err(format!(
                    "member {name:?} cannot be in a model set (relative, at most one directory \
                     level, characters A-Za-z0-9._-)"
                ));
            }
            if size == 0 {
                return Err(format!("member {name:?} is empty"));
            }
            if let Some((sub, _)) = name.split_once('/') {
                let d = out.join(sub);
                std::fs::create_dir_all(&d)
                    .map_err(|e| format!("creating {}: {e}", d.display()))?;
            }
            let dest = out.join(&name);
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o644)
                .open(&dest)
                .map_err(|e| format!("creating {}: {e}", dest.display()))?;
            let (bytes, sha256) = stream.member(size, Some(&mut f), &name)?;
            members.push(Member { path: name, bytes, sha256 });
        } else {
            stream.member(size, None, &name)?;
        }
        stream.skip_padding(size)?;
    }
    if members.is_empty() {
        return Err(match glob {
            Some(g) => format!("no member of the archive matches `{g}`"),
            None => "the archive holds no regular file".to_string(),
        });
    }
    Ok(members)
}

/// MUTANT only: a switched-off check is `!mutant_off() && <check fails>`.
#[allow(dead_code)]
fn mutant_off() -> bool {
    true
}

/// Builders for tar and gzip bytes, shared by this module's tests and the
/// stage tests: every archive a test needs is built in the test.
#[cfg(test)]
pub(crate) mod testkit {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    /// A ustar header block with a right checksum.
    pub(crate) fn header(name: &str, size: u64, kind: u8, link: &str) -> [u8; 512] {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..107].copy_from_slice(b"0000644");
        h[108..115].copy_from_slice(b"0000000");
        h[116..123].copy_from_slice(b"0000000");
        let sz = format!("{size:011o}");
        h[124..135].copy_from_slice(sz.as_bytes());
        h[136..147].copy_from_slice(b"00000000000");
        h[156] = kind;
        h[157..157 + link.len()].copy_from_slice(link.as_bytes());
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        seal(h)
    }

    /// Write the checksum of a header whose other fields are final.
    pub(crate) fn seal(mut h: [u8; 512]) -> [u8; 512] {
        h[148..156].fill(b' ');
        let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
        let ck = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(ck.as_bytes());
        h
    }

    /// The same header with the old GNU magic `ustar  \0`, as GNU tar writes.
    pub(crate) fn old_gnu(mut h: [u8; 512]) -> [u8; 512] {
        h[257..265].copy_from_slice(b"ustar  \0");
        seal(h)
    }

    /// One regular file under an old GNU header.
    pub(crate) fn gnu_file(name: &str, data: &[u8]) -> Vec<u8> {
        let mut b = old_gnu(header(name, data.len() as u64, b'0', "")).to_vec();
        b.extend_from_slice(data);
        pad(&mut b, data.len() as u64);
        b
    }

    pub(crate) fn pad(buf: &mut Vec<u8>, size: u64) {
        let p = (512 - size % 512) % 512;
        buf.extend(std::iter::repeat_n(0u8, p as usize));
    }

    /// One regular file.
    pub(crate) fn file(name: &str, data: &[u8]) -> Vec<u8> {
        let mut b = header(name, data.len() as u64, b'0', "").to_vec();
        b.extend_from_slice(data);
        pad(&mut b, data.len() as u64);
        b
    }

    /// An entry of another type (no data).
    pub(crate) fn other(name: &str, kind: u8, link: &str) -> Vec<u8> {
        header(name, 0, kind, link).to_vec()
    }

    pub(crate) fn tar(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut b: Vec<u8> = entries.concat();
        b.extend(std::iter::repeat_n(0u8, 1024));
        b
    }

    pub(crate) fn gz(raw: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::fast());
        e.write_all(raw).unwrap();
        e.finish().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::{file, gnu_file, gz, header, old_gnu, other, pad, seal, tar};
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::path::PathBuf;

    /// Small caps so a bomb is built and read in milliseconds; the default
    /// constants are pinned by their own test.
    const SMALL: Limits = Limits { member_bytes: 64 * 1024, total_bytes: 256 * 1024, members: 8 };

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-extract-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A gzip stream of members that are `size` zero bytes each, written to
    /// the encoder in chunks: tiny compressed, huge decompressed.
    fn bomb(members: &[(&str, u64)]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::fast());
        let zeros = vec![0u8; 64 * 1024];
        for (name, size) in members {
            e.write_all(&header(name, *size, b'0', "")).unwrap();
            let mut left = *size;
            while left > 0 {
                let n = left.min(zeros.len() as u64) as usize;
                e.write_all(&zeros[..n]).unwrap();
                left -= n as u64;
            }
            let mut p = Vec::new();
            pad(&mut p, *size);
            e.write_all(&p).unwrap();
        }
        e.write_all(&[0u8; 1024]).unwrap();
        e.finish().unwrap()
    }

    /// Extract `bytes` with `glob` and `lim` into a fresh dir; the dir comes back.
    fn run(
        tag: &str,
        bytes: &[u8],
        glob: Option<&str>,
        lim: &Limits,
    ) -> (Result<Vec<Member>, String>, PathBuf) {
        let dir = tmpdir(tag);
        let archive = dir.join("a.tgz");
        std::fs::write(&archive, bytes).unwrap();
        let out = dir.join("out");
        (extract(&archive, glob, &out, lim), out)
    }

    fn good() -> Vec<Vec<u8>> {
        vec![file("a.bin", b"alpha"), file("voices/b.bin", b"bravo!")]
    }

    fn refused(tag: &str, entries: &[Vec<u8>], lim: &Limits) -> String {
        let (r, _) = run(tag, &gz(&tar(entries)), None, lim);
        r.expect_err("the archive is refused")
    }

    #[test]
    fn the_default_caps_are_the_named_constants() {
        assert_eq!(MAX_MEMBER_BYTES, 32 * 1024 * 1024);
        assert_eq!(MAX_TOTAL_BYTES, 128 * 1024 * 1024);
        assert_eq!(Limits::DEFAULT.member_bytes, MAX_MEMBER_BYTES);
        assert_eq!(Limits::DEFAULT.total_bytes, MAX_TOTAL_BYTES);
        assert_eq!(Limits::DEFAULT.members, MAX_MEMBERS);
    }

    #[test]
    fn regular_files_are_extracted_hashed_and_a_glob_selects() {
        use std::os::unix::fs::PermissionsExt;
        let bytes = gz(&tar(&good()));
        let (r, out) = run("ok", &bytes, None, &SMALL);
        let got = r.expect("extracted");
        let paths: Vec<&str> = got.iter().map(|m| m.path.as_str()).collect();
        assert_eq!(paths, ["a.bin", "voices/b.bin"]);
        assert_eq!(got[0].bytes, 5);
        assert_eq!(got[0].sha256, hex::encode(Sha256::digest(b"alpha")));
        assert_eq!(std::fs::read(out.join("voices/b.bin")).unwrap(), b"bravo!");
        let mode = std::fs::metadata(out.join("a.bin")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
        // A plain (not gzipped) tar is read the same way.
        let (r, _) = run("ok-plain", &tar(&good()), None, &SMALL);
        assert_eq!(r.expect("plain tar").len(), 2);
        // The glob takes only what matches; the rest is read and not written.
        let (r, out) = run("ok-glob", &bytes, Some("voices/*.bin"), &SMALL);
        let got = r.expect("glob");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].path, "voices/b.bin");
        assert!(!out.join("a.bin").exists());
        let (r, _) = run("ok-noglob", &bytes, Some("*.pt"), &SMALL);
        assert!(r.expect_err("nothing matches").contains("matches"));
    }

    #[test]
    fn the_glob_does_not_cross_a_slash() {
        assert!(glob_match("*.bin", "a.bin"));
        assert!(!glob_match("*.bin", "voices/a.bin"));
        assert!(glob_match("voices/*", "voices/a.bin"));
        assert!(glob_match("v?ices/a.*", "voices/a.bin"));
        assert!(!glob_match("voices/*", "voices/x/a.bin"));
        assert!(glob_match("a.bin", "a.bin") && !glob_match("a.bi", "a.bin"));
    }

    #[test]
    fn a_symlink_is_refused() {
        let mut e = good();
        e.push(other("link.bin", b'2', "/etc/passwd"));
        let why = refused("symlink", &e, &SMALL);
        assert!(why.contains("a symlink"), "{why}");
        // The same archive without the symlink is taken: the refusal is the check's.
        let (r, _) = run("symlink-control", &gz(&tar(&good())), None, &SMALL);
        assert!(r.is_ok());
    }

    #[test]
    fn a_hard_link_is_refused() {
        let mut e = good();
        e.push(other("hard.bin", b'1', "a.bin"));
        let why = refused("hardlink", &e, &SMALL);
        assert!(why.contains("a hard link"), "{why}");
    }

    #[test]
    fn a_device_is_refused() {
        let kinds = [("chr", b'3', "character device"), ("blk", b'4', "block device")];
        for (tag, kind, what) in kinds {
            let mut e = good();
            e.push(other("dev.bin", kind, ""));
            let why = refused(tag, &e, &SMALL);
            assert!(why.contains(what), "{why}");
        }
    }

    #[test]
    fn a_fifo_a_sparse_entry_and_the_gnu_and_pax_tricks_are_refused() {
        let cases: [(u8, &str); 5] = [
            (b'6', "a FIFO"),
            (b'S', "a sparse file"),
            (b'L', "GNU long name"),
            (b'K', "GNU long name"),
            (b'x', "a pax extended header"),
        ];
        for (kind, what) in cases {
            let mut e = good();
            e.push(other("odd.bin", kind, ""));
            let why = refused(&format!("odd-{kind}"), &e, &SMALL);
            assert!(why.contains(what), "{kind}: {why}");
        }
    }

    #[test]
    fn a_dot_dot_component_is_refused() {
        for name in ["../escape.bin", "voices/../b.bin"] {
            let mut e = good();
            e.push(file(name, b"x"));
            let why = refused("dotdot", &e, &SMALL);
            assert!(why.contains("`..` component"), "{name}: {why}");
        }
    }

    #[test]
    fn an_absolute_path_is_refused() {
        let mut e = good();
        e.push(file("/etc/cron.d/x", b"x"));
        let why = refused("absolute", &e, &SMALL);
        assert!(why.contains("absolute path"), "{why}");
    }

    #[test]
    fn a_name_that_changes_under_normalisation_is_refused() {
        for name in ["./c.bin", "voices//c.bin", "voices/c.bin/"] {
            let mut e = good();
            e.push(file(name, b"x"));
            let why = refused("normal", &e, &SMALL);
            assert!(why.contains("normalisation"), "{name}: {why}");
        }
    }

    #[test]
    fn a_duplicate_name_is_refused() {
        let mut e = good();
        e.push(file("a.bin", b"again"));
        let why = refused("dup", &e, &SMALL);
        assert!(why.contains("appears twice"), "{why}");
        let mut e = good();
        e.push(file("A.BIN", b"case"));
        let why = refused("dup-case", &e, &SMALL);
        assert!(why.contains("appears twice"), "{why}");
    }

    #[test]
    fn a_selected_member_must_pass_the_set_path_rule() {
        for name in ["a/b/c.bin", "sp ace.bin", "caf\u{e9}.bin"] {
            let mut e = good();
            e.push(file(name, b"x"));
            let why = refused("setpath", &e, &SMALL);
            assert!(why.contains("cannot be in a model set"), "{name}: {why}");
        }
        // Not selected, it is only held to the path-safety checks.
        let mut e = good();
        e.push(file("a/b/c.bin", b"x"));
        let (r, _) = run("setpath-glob", &gz(&tar(&e)), Some("a.bin"), &SMALL);
        assert_eq!(r.expect("the deep member is not selected").len(), 1);
    }

    #[test]
    fn one_member_past_the_per_member_cap_is_a_refusal_while_it_streams() {
        // 1 MiB of zeros: a few hundred bytes compressed, 16 times the cap.
        let gzbytes = bomb(&[("a.bin", 1 << 20)]);
        assert!(gzbytes.len() < 8 * 1024, "the bomb is {} bytes compressed", gzbytes.len());
        let (r, _) = run("bomb-member", &gzbytes, None, &SMALL);
        let why = r.expect_err("past the per-member cap");
        assert!(why.contains("per-member cap"), "{why}");
        // Just under the cap is taken.
        let (r, _) = run("bomb-member-ok", &bomb(&[("a.bin", 60 * 1024)]), None, &SMALL);
        assert_eq!(r.expect("under the cap")[0].bytes, 60 * 1024);
    }

    #[test]
    fn the_default_per_member_cap_holds_on_a_real_size() {
        let size = MAX_MEMBER_BYTES + 1;
        let gzbytes = bomb(&[("a.bin", size)]);
        assert!(gzbytes.len() < 1 << 20, "{} bytes compressed", gzbytes.len());
        let (r, _) = run("bomb-default", &gzbytes, None, &Limits::DEFAULT);
        assert!(r.expect_err("past 32 MiB").contains("per-member cap"));
    }

    /// Eight 60 KiB members: each under the 64 KiB cap, 480 KiB in all.
    fn eight_members() -> Vec<(&'static str, u64)> {
        let names = ["a0.bin", "a1.bin", "a2.bin", "a3.bin", "a4.bin", "a5.bin", "a6.bin"];
        names.iter().chain(["a7.bin"].iter()).map(|n| (*n, 60 * 1024)).collect()
    }

    #[test]
    fn many_members_each_under_the_cap_stop_at_the_total_cap() {
        // Eight members of 60 KiB are 480 KiB against a 256 KiB total, and
        // each is under the 64 KiB per-member cap.
        let members = eight_members();
        let gzbytes = bomb(&members);
        assert!(gzbytes.len() < 16 * 1024, "{} bytes compressed", gzbytes.len());
        let (r, _) = run("bomb-total", &gzbytes, None, &SMALL);
        let why = r.expect_err("past the total cap");
        assert!(why.contains("total cap"), "{why}");
        // Three of them fit.
        let (r, _) = run("bomb-total-ok", &bomb(&members[..3]), None, &SMALL);
        assert_eq!(r.expect("under the total").len(), 3);
    }

    #[test]
    fn a_skipped_member_counts_against_the_total_too() {
        let members = eight_members();
        let (r, _) = run("bomb-skip", &bomb(&members), Some("a0.bin"), &SMALL);
        assert!(r.expect_err("the rest is still decompressed").contains("total cap"));
    }

    #[test]
    fn more_entries_than_the_member_cap_is_a_refusal() {
        let many: Vec<Vec<u8>> = (0..9).map(|i| file(&format!("f{i}.bin"), b"x")).collect();
        let why = refused("members", &many, &SMALL);
        assert!(why.contains("more than 8 entries"), "{why}");
        assert!(run("members-ok", &gz(&tar(&many[..8])), None, &SMALL).0.is_ok());
    }

    /// A directory entry as `tar` writes it: typeflag 5, the given size field
    /// (0 in a real archive), mode 0777 and an owner, old GNU magic.
    fn dir_entry(name: &str, size: u64) -> Vec<u8> {
        let mut h = header(name, size, b'5', "");
        h[100..107].copy_from_slice(b"0000777");
        h[265..269].copy_from_slice(b"root");
        old_gnu(seal(h)).to_vec()
    }

    #[test]
    fn a_directory_entry_creates_nothing_whatever_its_mode_and_owner() {
        use std::os::unix::fs::PermissionsExt;
        let e = vec![dir_entry("voices/", 0), file("voices/a.pt", b"alpha")];
        let (r, out) = run("dir-skip", &gz(&tar(&e)), None, &SMALL);
        let got = r.expect("the directory entry is skipped");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].path, "voices/a.pt");
        let top: Vec<_> = std::fs::read_dir(&out)
            .unwrap()
            .map(|d| d.unwrap().file_name())
            .collect();
        assert_eq!(top, ["voices"]);
        // `voices` was made by create_dir_all for the file, so it has the mode
        // any create_dir_all gets under this umask, not the entry's 0777.
        let reference = out.with_file_name("dir-skip-reference");
        std::fs::create_dir_all(&reference).unwrap();
        let want = std::fs::metadata(&reference).unwrap().permissions().mode();
        let mode = std::fs::metadata(out.join("voices")).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, want & 0o7777, "the mode of the directory entry was applied");
        // A directory entry no file lives under leaves nothing at all.
        let e = vec![dir_entry("extra/", 0), file("a.pt", b"alpha")];
        let (r, out) = run("dir-skip-bare", &gz(&tar(&e)), Some("*.pt"), &SMALL);
        assert_eq!(r.expect("extracted").len(), 1);
        assert!(!out.join("extra").exists());
        // A directory entry alone is no regular file.
        let why = refused("dir-only", &[dir_entry("voices/", 0)], &SMALL);
        assert!(why.contains("no regular file"), "{why}");
        // A directory entry passes the name checks, less one trailing slash.
        for name in ["../x/", "/abs/", "voices//", "./"] {
            let why = refused("dir-name", &[dir_entry(name, 0)], &SMALL);
            assert!(why.contains("member"), "{name}: {why}");
        }
    }

    #[test]
    fn a_directory_entry_with_a_size_is_refused() {
        let why = refused("dir-size", &[dir_entry("voices/", 512), file("a.pt", b"x")], &SMALL);
        assert!(why.contains("has a size"), "{why}");
        // The same archive with a size-0 entry is taken: the refusal is the check's.
        let e = vec![dir_entry("voices/", 0), file("a.pt", b"x")];
        assert!(run("dir-size-control", &gz(&tar(&e)), None, &SMALL).0.is_ok());
    }

    #[test]
    fn the_real_old_gnu_layout_extracts() {
        let e = vec![
            dir_entry("voices/", 0),
            gnu_file("voices/NATM2.pt", b"first voice"),
            gnu_file("voices/NATF0.pt", b"second voice"),
            gnu_file("voices/VARF1.pt", b"third voice"),
        ];
        let (r, out) = run("gnu-layout", &gz(&tar(&e)), Some("voices/*.pt"), &SMALL);
        let got = r.expect("the real layout extracts");
        let paths: Vec<&str> = got.iter().map(|m| m.path.as_str()).collect();
        assert_eq!(paths, ["voices/NATM2.pt", "voices/NATF0.pt", "voices/VARF1.pt"]);
        assert_eq!(got[0].sha256, hex::encode(Sha256::digest(b"first voice")));
        assert_eq!(got[1].sha256, hex::encode(Sha256::digest(b"second voice")));
        assert_eq!(got[2].sha256, hex::encode(Sha256::digest(b"third voice")));
        assert_eq!(std::fs::read(out.join("voices/VARF1.pt")).unwrap(), b"third voice");
    }

    #[test]
    fn unselected_members_count_toward_the_entry_cap() {
        let lim = Limits { members: 3, ..SMALL };
        let mut e = vec![file("a.pt", b"x")];
        e.extend((0..3).map(|i| file(&format!("skip{i}.bin"), b"x")));
        let (r, _) = run("cap-unselected", &gz(&tar(&e)), Some("*.pt"), &lim);
        let why = r.expect_err("four entries against a cap of three");
        assert!(why.contains("more than 3 entries"), "{why}");
        // Three entries, one selected, are taken.
        let (r, _) = run("cap-unselected-ok", &gz(&tar(&e[..3])), Some("*.pt"), &lim);
        assert_eq!(r.expect("three entries").len(), 1);
    }

    #[test]
    fn a_directory_entry_counts_toward_the_entry_cap() {
        let lim = Limits { members: 3, ..SMALL };
        let mut e = vec![dir_entry("voices/", 0)];
        e.extend((0..3).map(|i| file(&format!("a{i}.pt"), b"x")));
        let why = run("cap-dir", &gz(&tar(&e)), None, &lim).0.expect_err("four entries");
        assert!(why.contains("more than 3 entries"), "{why}");
        // The directory entry and two files are three entries: taken.
        let got = run("cap-dir-ok", &gz(&tar(&e[..3])), None, &lim).0.expect("three entries");
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn a_damaged_or_empty_or_truncated_archive_is_refused() {
        let mut raw = tar(&good());
        raw[10] ^= 0x55;
        let why = run("bad-sum", &gz(&raw), None, &SMALL).0.expect_err("checksum");
        assert!(why.contains("checksum"), "{why}");
        let why = refused("empty-member", &[file("e.bin", b"")], &SMALL);
        assert!(why.contains("is empty"), "{why}");
        let cut = tar(&[file("a.bin", &[7u8; 2000])]);
        let why = run("cut", &gz(&cut[..1024]), None, &SMALL).0.expect_err("truncated");
        assert!(why.contains("cut short") || why.contains("ends inside"), "{why}");
        let why = run("junk", &gz(&[9u8; 700]), None, &SMALL).0.expect_err("not a tar");
        assert!(why.contains("checksum"), "{why}");
        let why = run("none", &gz(&tar(&[])), None, &SMALL).0.expect_err("no file");
        assert!(why.contains("no regular file"), "{why}");
    }

    /// One regular-file entry whose header is `h` (re-sealed), then `data`.
    fn entry_of(h: [u8; 512], data: &[u8]) -> Vec<u8> {
        let mut b = seal(h).to_vec();
        b.extend_from_slice(data);
        pad(&mut b, data.len() as u64);
        b
    }

    #[test]
    fn an_archive_cut_inside_a_header_is_refused() {
        // good(): a.bin takes 512 + 512 bytes, so the second header starts at 1024.
        let raw = tar(&good());
        let why = run("cut-header", &gz(&raw[..1024 + 100]), None, &SMALL)
            .0
            .expect_err("cut inside the second header");
        assert!(why.contains("ends inside a header"), "{why}");
    }

    #[test]
    fn an_archive_cut_inside_a_members_padding_is_refused() {
        // The 5 bytes of a.bin are whole; 100 of its 507 padding bytes follow.
        let raw = tar(&good());
        let why = run("cut-padding", &gz(&raw[..512 + 5 + 100]), None, &SMALL)
            .0
            .expect_err("cut inside the padding");
        assert!(why.contains("ends inside a member's padding"), "{why}");
    }

    #[test]
    fn an_archive_cut_inside_a_members_data_is_cut_short() {
        let raw = tar(&[file("a.bin", &[7u8; 100])]);
        let why = run("cut-data", &gz(&raw[..512 + 10]), None, &SMALL)
            .0
            .expect_err("cut inside the data");
        assert!(why.contains("is cut short"), "{why}");
    }

    #[test]
    fn a_name_that_is_not_utf8_is_refused() {
        let mut h = header("a.bin", 1, b'0', "");
        h[0] = 0xff;
        let why = refused("utf8", &[entry_of(h, b"x")], &SMALL);
        assert!(why.contains("not UTF-8"), "{why}");
    }

    #[test]
    fn a_member_with_no_name_is_refused() {
        let h = header("", 1, b'0', "");
        let why = refused("noname", &[entry_of(h, b"x")], &SMALL);
        assert!(why.contains("empty name"), "{why}");
    }

    #[test]
    fn a_size_field_that_is_not_octal_is_refused() {
        let mut base256 = [0u8; 12];
        base256[0] = 0x80;
        base256[11] = 5;
        let blank = [b' '; 12];
        let junk = *b"7777777z7777";
        let fields: [(&str, [u8; 12]); 3] = [("base256", base256), ("blank", blank), ("junk", junk)];
        for (tag, field) in fields {
            let mut h = header("a.bin", 1, b'0', "");
            h[124..136].copy_from_slice(&field);
            let why = refused(tag, &[entry_of(h, b"x")], &SMALL);
            assert!(why.contains("size field"), "{tag}: {why}");
        }
    }

    #[test]
    fn an_octal_field_takes_no_sign() {
        assert_eq!(octal(b"0000017\0"), Some(15));
        assert_eq!(octal(b"+7\0"), None);
        assert_eq!(octal(b"-7\0"), None);
    }

    #[test]
    fn a_member_never_overwrites_a_file_or_follows_a_link_in_the_output_dir() {
        let dir = tmpdir("create-new");
        let archive = dir.join("a.tgz");
        std::fs::write(&archive, gz(&tar(&[file("a.bin", b"new")]))).unwrap();
        // A file already at the member's name is left alone, and is a refusal.
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("a.bin"), b"old").unwrap();
        let why = extract(&archive, None, &out, &SMALL).expect_err("the file exists");
        assert!(why.contains("creating"), "{why}");
        assert_eq!(std::fs::read(out.join("a.bin")).unwrap(), b"old");
        // A link planted at the member's name is not written through.
        let out2 = dir.join("out2");
        std::fs::create_dir_all(&out2).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, out2.join("a.bin")).unwrap();
        let why = extract(&archive, None, &out2, &SMALL).expect_err("the link exists");
        assert!(why.contains("creating"), "{why}");
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    }

    #[test]
    fn a_ustar_prefix_is_part_of_the_name_and_judged_with_it() {
        let mut h = header("a.bin", 1, b'0', "");
        h[345..351].copy_from_slice(b"voices");
        let (r, _) = run("prefix", &gz(&tar(&[entry_of(h, b"x")])), None, &SMALL);
        assert_eq!(r.expect("prefixed")[0].path, "voices/a.bin");
        let mut h = header("a.bin", 1, b'0', "");
        h[345..347].copy_from_slice(b"..");
        let why = refused("prefix-dotdot", &[entry_of(h, b"x")], &SMALL);
        assert!(why.contains("`..` component"), "{why}");
    }
}
