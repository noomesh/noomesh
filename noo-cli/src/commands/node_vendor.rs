// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The Mac applier's half of the staged vendor CLI (i83 E1e): what
//! `scripts/noo-apply.sh`'s vendor_install block does on Linux, under the
//! enrolling user's `~/noomesh` instead of `/opt/noo/vendor`.
//!
//! `<base>/vendor/<name>/<version>/` holds the unpacked CLI (and
//! `<base>/vendor/<runtime>/<version>/` its runtime), and the wrapper
//! `cluster_vendor::wrapper_script` renders goes to `<base>/bin/<cli>`,
//! which `run-agent.sh` and `run-harness.sh` put on PATH — so the agent's
//! vendor-CLI check (`cliOnPath`) and the harness's driver both find it.
//! Everything here runs as the user (the darwin applier has already
//! lowered privileges for the user's tree); `tar` is the system bsdtar,
//! which reads tgz, tar.xz and zip alike.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use super::cluster_vendor::{wrapper_script, WrapperRuntime};

/// The vendor kinds' manifests, parsed and judged.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Manifest {
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub unpack: String,
    pub entry: String,
    pub runtime: Option<String>,
    pub runtime_version: Option<String>,
    pub bin_dir: String,
}

fn re_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.as_bytes()[0].is_ascii_lowercase()
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn re_version(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
}
fn re_path(s: &str) -> bool {
    !s.is_empty() && s.len() <= 200 && !s.starts_with('/')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._/@+-".contains(&b))
        && s.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

/// Parse and judge a manifest (`runtime` = the vendor-runtime one), the
/// same rules as the Linux applier's vendor_manifest_ok.
pub(crate) fn parse_manifest(bytes: &[u8], runtime: bool) -> Result<Manifest, String> {
    let kind = if runtime { "vendor-runtime" } else { "vendor-cli" };
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| format!("{kind}: manifest does not parse ({e})"))?;
    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
    let m = Manifest {
        name: s("name"),
        version: s("version"),
        sha256: s("sha256"),
        unpack: s("unpack"),
        entry: s("entry"),
        runtime: v["runtime"].as_str().map(str::to_string),
        runtime_version: v["runtime_version"].as_str().map(str::to_string),
        bin_dir: s("bin_dir"),
    };
    let refuse = |why: String| Err(format!("REFUSED {kind} — {why}"));
    if !re_name(&m.name) {
        return refuse(format!("name '{}' is not a plain name", m.name));
    }
    if m.name.starts_with("noo") {
        return refuse(format!("name '{}' would shadow a noomesh binary", m.name));
    }
    if !re_version(&m.version) {
        return refuse(format!("version '{}' is not a plain version", m.version));
    }
    if m.sha256.len() != 64 || !m.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return refuse("sha256 is not 64 lowercase hex".into());
    }
    if !["tgz", "tar.xz", "zip", "none"].contains(&m.unpack.as_str()) {
        return refuse(format!("unpack '{}' is not tgz, tar.xz, zip or none", m.unpack));
    }
    if runtime {
        if s("kind") != "runtime" {
            return refuse("the manifest is not a runtime's".into());
        }
        if !re_path(&m.bin_dir) {
            return refuse("bin_dir is not a plain relative path".into());
        }
        if m.unpack == "none" {
            return refuse("a runtime is an archive".into());
        }
    } else {
        if m.name == "node" {
            return refuse("a CLI may not be named node".into());
        }
        if !re_path(&m.entry) {
            return refuse("entry is not a plain relative path".into());
        }
        match (&m.runtime, &m.runtime_version) {
            (None, None) => {}
            (Some(r), Some(rv)) if re_name(r) && re_version(rv) => {}
            _ => return refuse("runtime and runtime_version must both be plain, or both null".into()),
        }
    }
    Ok(m)
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// Before anything installs: each vendor payload rides with its manifest,
/// the manifest is well-formed, and the payload hashes to it.
pub(crate) fn check(payloads: &BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    for (kind, rt) in [("vendor-cli", false), ("vendor-runtime", true)] {
        let mk = format!("{kind}-manifest");
        match (payloads.get(kind), payloads.get(&mk)) {
            (None, None) => continue,
            (Some(p), Some(m)) => {
                let m = parse_manifest(m, rt)?;
                if sha256_hex(p) != m.sha256 {
                    return Err(format!("REFUSED {kind} — the payload does not hash to its manifest's sha256"));
                }
            }
            _ => return Err(format!("REFUSED {kind} — the payload and its manifest must ride together")),
        }
    }
    if let (Some(_), Some(cm)) = (payloads.get("vendor-runtime"), payloads.get("vendor-cli-manifest")) {
        let c = parse_manifest(cm, false)?;
        let r = parse_manifest(&payloads["vendor-runtime-manifest"], true)?;
        if c.runtime.as_deref() != Some(r.name.as_str()) {
            return Err("REFUSED vendor-runtime — the CLI's manifest names a different runtime".into());
        }
    }
    Ok(())
}

/// A native executable for this platform: Mach-O (64-bit or universal)
/// on a Mac, ELF elsewhere.
pub(crate) fn native_executable(head: &[u8], darwin: bool) -> bool {
    let m = head.get(..4).unwrap_or(&[]);
    if darwin {
        matches!(m, [0xcf, 0xfa, 0xed, 0xfe] | [0xca, 0xfe, 0xba, 0xbe])
    } else {
        m == b"\x7fELF"
    }
}

fn run(cmd: &mut Command) -> Result<String, String> {
    let out = cmd.output().map_err(|e| format!("{cmd:?}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{:?} failed: {}", cmd.get_program(), String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Unpack `archive` into the empty `dest`, after judging its member list:
/// nothing absolute, nothing climbing out with `..`, no absolute symlink.
fn unpack(tar: &str, archive: &Path, dest: &Path) -> Result<(), String> {
    let list = run(Command::new(tar).arg("-tf").arg(archive))?;
    if list.lines().any(|l| l.starts_with('/') || l.split('/').any(|c| c == "..")) {
        return Err("the archive names a path outside its own directory".into());
    }
    let long = run(Command::new(tar).arg("-tvf").arg(archive))?;
    if long.lines().any(|l| l.contains(" -> /")) {
        return Err("the archive carries an absolute symlink".into());
    }
    run(Command::new(tar).arg("-xf").arg(archive).arg("-C").arg(dest)).map(|_| ())
}

/// One installed payload: (kind, unchanged, report line).
pub(crate) type Done = (&'static str, bool, String);

/// The applier's atomic as-the-user writer: (path, bytes, mode).
pub(crate) type Writer<'a> = &'a dyn Fn(&Path, &[u8], u32) -> Result<(), String>;

/// Install one payload under `<vendor>/<name>/<version>`; `Ok(true)` when
/// that version, from those exact bytes, was already there.
fn install_one(tar: &str, vendor: &Path, payload: &[u8], m: &Manifest, runtime: bool, darwin: bool) -> Result<bool, String> {
    let dest = vendor.join(&m.name).join(&m.version);
    if std::fs::read_to_string(dest.join(".noo-sha256")).is_ok_and(|s| s.trim() == m.sha256) {
        return Ok(true);
    }
    let parent = vendor.join(&m.name);
    std::fs::create_dir_all(&parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    let stage = parent.join(format!(".{}.next", m.version));
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage).map_err(|e| format!("{}: {e}", stage.display()))?;
    let fail = |e: String| -> Result<bool, String> {
        let _ = std::fs::remove_dir_all(&stage);
        Err(format!("{}: {e}", if runtime { "vendor-runtime" } else { "vendor-cli" }))
    };
    use std::os::unix::fs::PermissionsExt;
    if m.unpack == "none" {
        let f = stage.join(&m.entry);
        if let Err(e) = std::fs::write(&f, payload).and_then(|_| std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755))) {
            return fail(e.to_string());
        }
    } else {
        let archive = parent.join(format!(".{}.payload", m.version));
        if let Err(e) = std::fs::write(&archive, payload) {
            return fail(e.to_string());
        }
        let r = unpack(tar, &archive, &stage);
        let _ = std::fs::remove_file(&archive);
        if let Err(e) = r {
            return fail(e);
        }
    }
    if runtime {
        // One top-level directory becomes the version root.
        let entries: Vec<PathBuf> = std::fs::read_dir(&stage).map(|rd| rd.flatten().map(|e| e.path()).collect()).unwrap_or_default();
        if let [only] = entries.as_slice() {
            if only.is_dir() {
                let flat = parent.join(format!(".{}.flat", m.version));
                let _ = std::fs::remove_dir_all(&flat);
                if let Err(e) = std::fs::rename(only, &flat).and_then(|_| std::fs::remove_dir(&stage)).and_then(|_| std::fs::rename(&flat, &stage)) {
                    return fail(e.to_string());
                }
            }
        }
        if !stage.join(&m.bin_dir).join(&m.name).is_file() {
            return fail(format!("{}/{} is not in the runtime archive", m.bin_dir, m.name));
        }
        let _ = std::fs::write(stage.join(".noo-bin-dir"), format!("{}\n", m.bin_dir));
    } else {
        let entry = stage.join(&m.entry);
        let head = std::fs::read(&entry).map(|b| b.into_iter().take(4).collect::<Vec<u8>>());
        let Ok(head) = head else { return fail(format!("entry {} is not in the artefact", m.entry)) };
        if m.runtime.is_none() && !native_executable(&head, darwin) {
            return fail(format!("entry {} is not a native executable for this platform", m.entry));
        }
        let _ = std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o755));
    }
    if let Err(e) = std::fs::write(stage.join(".noo-sha256"), format!("{}\n", m.sha256)) {
        return fail(e.to_string());
    }
    let _ = std::fs::remove_dir_all(&dest);
    if let Err(e) = std::fs::rename(&stage, &dest) {
        return fail(e.to_string());
    }
    Ok(false)
}

const MARK: &str = "# noomesh vendor wrapper:";

/// Remove `name`'s versions other than `keep` that no wrapper in `bin`
/// still names.
fn prune(vendor: &Path, bin: &Path, name: &str, keep: &str) {
    let wrappers: Vec<String> = std::fs::read_dir(bin).map(|rd| rd.flatten()
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .filter(|t| t.starts_with("#!/bin/sh") && t.lines().take(2).any(|l| l.starts_with(MARK)))
        .collect()).unwrap_or_default();
    let Ok(rd) = std::fs::read_dir(vendor.join(name)) else { return };
    for e in rd.flatten() {
        let v = e.file_name().to_string_lossy().into_owned();
        if v == keep || v.starts_with('.') || !e.path().is_dir() {
            continue;
        }
        let needle = format!("{}/{name}/{v}/", vendor.display());
        if !wrappers.iter().any(|w| w.contains(&needle)) {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// Install what the bundle carries: the runtime first, then the CLI, its
/// wrapper at `<base>/bin/<cli>` (written by `write`, the applier's own
/// as-the-user atomic writer) and the pruning. Returns one entry per
/// payload for the apply report; `check` has already judged them.
pub(crate) fn install(
    payloads: &BTreeMap<String, Vec<u8>>,
    base: &Path,
    tar: &str,
    darwin: bool,
    write: Writer,
) -> Result<Vec<Done>, String> {
    let vendor = base.join("vendor");
    let bin = base.join("bin");
    let mut done: Vec<Done> = Vec::new();
    let mut rt: Option<Manifest> = None;
    if let Some(p) = payloads.get("vendor-runtime") {
        let m = parse_manifest(&payloads["vendor-runtime-manifest"], true)?;
        let same = install_one(tar, &vendor, p, &m, true, darwin)?;
        done.push(("vendor-runtime", same, format!("vendor-runtime: {} {} {}", m.name, m.version, if same { "unchanged" } else { "installed" })));
        rt = Some(m);
    }
    let Some(p) = payloads.get("vendor-cli") else { return Ok(done) };
    let m = parse_manifest(&payloads["vendor-cli-manifest"], false)?;
    let bin_dir = match (&m.runtime, &m.runtime_version, &rt) {
        (Some(r), Some(rv), Some(x)) if &x.name == r && &x.version == rv => Some(x.bin_dir.clone()),
        (Some(r), Some(rv), _) => {
            let b = std::fs::read_to_string(vendor.join(r).join(rv).join(".noo-bin-dir"))
                .map_err(|_| format!("REFUSED vendor-cli — {} runs on {r} {rv}, which neither this bundle nor this node carries", m.name))?;
            let b = b.trim().to_string();
            if !re_path(&b) {
                return Err(format!("REFUSED vendor-cli — the installed {r} {rv} has no usable bin_dir"));
            }
            Some(b)
        }
        _ => None,
    };
    let same = install_one(tar, &vendor, p, &m, false, darwin)?;
    let vroot = vendor.display().to_string();
    let wrapper = match (&m.runtime, &m.runtime_version, &bin_dir) {
        (Some(r), Some(rv), Some(b)) => wrapper_script(&vroot, &m.name, &m.version, &m.entry,
            Some(&WrapperRuntime { name: r, version: rv, bin_dir: b })),
        _ => wrapper_script(&vroot, &m.name, &m.version, &m.entry, None),
    };
    let wpath = bin.join(&m.name);
    let wrapper_same = std::fs::read_to_string(&wpath).is_ok_and(|t| t == wrapper);
    if !wrapper_same {
        let _ = std::fs::create_dir_all(&bin);
        write(&wpath, wrapper.as_bytes(), 0o755)?;
    }
    prune(&vendor, &bin, &m.name, &m.version);
    if let (Some(r), Some(rv)) = (&m.runtime, &m.runtime_version) {
        prune(&vendor, &bin, r, rv);
    }
    let unchanged = same && wrapper_same;
    done.push(("vendor-cli", unchanged, if unchanged {
        format!("vendor-cli: {} {} unchanged — already installed, nothing to do", m.name, m.version)
    } else {
        format!("vendor-cli: {} {} installed ({}, wrapper {})", m.name, m.version, vendor.join(&m.name).join(&m.version).display(), wpath.display())
    }));
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::cluster_vendor::manifest_text;

    const MACHO: &[u8] = &[0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0];

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-node-vendor-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A gzipped tar of `members` (name, bytes), made with the system tar.
    fn tgz(dir: &Path, members: &[(&str, &[u8])]) -> Vec<u8> {
        let src = dir.join("src");
        let _ = std::fs::remove_dir_all(&src);
        for (n, b) in members {
            let p = src.join(n);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b).unwrap();
        }
        let out = dir.join("a.tgz");
        let names: Vec<&str> = members.iter().map(|(n, _)| *n).collect();
        let st = Command::new("tar").arg("-czf").arg(&out).arg("-C").arg(&src).args(&names).status().unwrap();
        assert!(st.success());
        let b = std::fs::read(&out).unwrap();
        let _ = std::fs::remove_dir_all(&src);
        b
    }

    fn cli_manifest(p: &[u8], name: &str, version: &str, entry: &str, unpack: &str, rt: Option<(&str, &str)>) -> Vec<u8> {
        let sha = sha256_hex(p);
        manifest_text(&[("kind", Some(name)), ("name", Some(name)), ("version", Some(version)), ("sha256", Some(&sha)),
            ("format", Some("tarball")), ("unpack", Some(unpack)), ("entry", Some(entry)),
            ("runtime", rt.map(|r| r.0)), ("runtime_version", rt.map(|r| r.1))]).into_bytes()
    }

    fn write(p: &Path, b: &[u8], mode: u32) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(p, b).map_err(|e| e.to_string())?;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())
    }

    #[test]
    fn a_native_cli_lands_under_the_users_tree_with_a_wrapper_and_is_idempotent() {
        let d = tmp("native");
        let art = tgz(&d, &[("copilot", MACHO)]);
        let mut p = BTreeMap::new();
        p.insert("vendor-cli".to_string(), art.clone());
        p.insert("vendor-cli-manifest".to_string(), cli_manifest(&art, "copilot", "1.0.0", "copilot", "tgz", None));
        check(&p).unwrap();
        let base = d.join("noomesh");
        let done = install(&p, &base, "tar", true, &write).unwrap();
        assert_eq!(done.len(), 1);
        assert!(!done[0].1 && done[0].2.starts_with("vendor-cli: copilot 1.0.0 installed"), "{done:?}");
        let w = std::fs::read_to_string(base.join("bin/copilot")).unwrap();
        assert_eq!(w, wrapper_script(&base.join("vendor").display().to_string(), "copilot", "1.0.0", "copilot", None));
        assert!(w.contains(&format!("exec \"{}/noomesh/vendor/copilot/1.0.0/copilot\"", d.display())));
        let again = install(&p, &base, "tar", true, &write).unwrap();
        assert!(again[0].1 && again[0].2.contains("unchanged"), "{again:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_new_version_prunes_the_old_and_a_runtime_is_kept_while_named() {
        let d = tmp("runtime");
        let base = d.join("noomesh");
        let node = tgz(&d, &[("node-v22-darwin-arm64/bin/node", b"#!/bin/sh\n")]);
        let rtm = manifest_text(&[("kind", Some("runtime")), ("name", Some("node")), ("version", Some("22.11.0")),
            ("sha256", Some(&sha256_hex(&node))), ("unpack", Some("tgz")), ("bin_dir", Some("bin"))]).into_bytes();
        let cli = tgz(&d, &[("package/index.js", b"1")]);
        let mut p = BTreeMap::new();
        p.insert("vendor-runtime".to_string(), node);
        p.insert("vendor-runtime-manifest".to_string(), rtm);
        p.insert("vendor-cli".to_string(), cli.clone());
        p.insert("vendor-cli-manifest".to_string(), cli_manifest(&cli, "copilot", "1.0.0", "package/index.js", "tgz", Some(("node", "22.11.0"))));
        check(&p).unwrap();
        install(&p, &base, "tar", true, &write).unwrap();
        assert!(base.join("vendor/node/22.11.0/bin/node").is_file(), "flattened");
        let w = std::fs::read_to_string(base.join("bin/copilot")).unwrap();
        assert!(w.contains(&format!("PATH=\"{}/node/22.11.0/bin:$PATH\"", base.join("vendor").display())), "{w}");
        // The CLI alone, next version: the runtime is found on disk, the old CLI pruned.
        let cli2 = tgz(&d, &[("package/index.js", b"2")]);
        let mut p2 = BTreeMap::new();
        p2.insert("vendor-cli".to_string(), cli2.clone());
        p2.insert("vendor-cli-manifest".to_string(), cli_manifest(&cli2, "copilot", "1.1.0", "package/index.js", "tgz", Some(("node", "22.11.0"))));
        install(&p2, &base, "tar", true, &write).unwrap();
        let versions: Vec<String> = std::fs::read_dir(base.join("vendor/copilot")).unwrap().flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(versions, ["1.1.0"]);
        assert!(base.join("vendor/node/22.11.0").is_dir());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn refusals_match_the_linux_applier() {
        let d = tmp("refuse");
        let art = tgz(&d, &[("copilot", b"#!/bin/sh\n")]);
        let mk = |m: Vec<u8>| -> BTreeMap<String, Vec<u8>> {
            [("vendor-cli".to_string(), art.clone()), ("vendor-cli-manifest".to_string(), m)].into_iter().collect()
        };
        // Tampered payload.
        let mut p = mk(cli_manifest(&art, "copilot", "1.0.0", "copilot", "tgz", None));
        p.get_mut("vendor-cli").unwrap().push(0);
        assert!(check(&p).unwrap_err().contains("does not hash"));
        // Manifest values.
        for (entry, name, why) in [("../x", "copilot", "entry"), ("copilot", "noo-gateway", "shadow"), ("copilot", "node", "named node")] {
            let e = check(&mk(cli_manifest(&art, name, "1.0.0", entry, "tgz", None))).unwrap_err();
            assert!(e.contains(why), "{e}");
        }
        // Alone.
        let alone: BTreeMap<String, Vec<u8>> = [("vendor-cli".to_string(), art.clone())].into_iter().collect();
        assert!(check(&alone).unwrap_err().contains("ride together"));
        // Not a native executable (a script with no runtime).
        let p = mk(cli_manifest(&art, "copilot", "1.0.0", "copilot", "tgz", None));
        let e = install(&p, &d.join("noomesh"), "tar", true, &write).unwrap_err();
        assert!(e.contains("not a native executable"), "{e}");
        assert!(!d.join("noomesh/bin/copilot").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn native_means_mach_o_on_a_mac_and_elf_elsewhere() {
        assert!(native_executable(MACHO, true));
        assert!(native_executable(&[0xca, 0xfe, 0xba, 0xbe], true));
        assert!(!native_executable(b"\x7fELF", true));
        assert!(native_executable(b"\x7fELF", false));
        assert!(!native_executable(b"#!/b", false));
    }
}
