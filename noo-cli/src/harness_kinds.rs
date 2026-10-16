// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `config/harness-kinds.json`, as the CLI reads it: the kind names a
//! `--kind` may name, and — for a kind whose vendor CLI the controller
//! stages — where that CLI (and the runtime it needs) comes from and the
//! sha256 it must hash to (i83 E1e).
//!
//! The gateway (`gateway-rust/src/harness_kinds.rs`) and the node agent read
//! the same file. Only the fields the CLI acts on are typed here; the rest
//! of a row is ignored. `runtimes` and `distribution` are optional: a kind
//! with a `cli` and no `distribution` is a manual install, and a table with
//! no `runtimes` names none.
//!
//! A pin is `sha256` keyed `any` (one artefact for every platform, an npm
//! tarball) or keyed by noomesh's own platform facts, `<os>-<arch>` with os
//! `linux`/`macos` and arch `x86_64`/`aarch64`. `names` maps those facts to
//! the vendor's own spelling inside the `source` URL template, which may use
//! `{version}`, `{os}` and `{arch}`.

use std::collections::BTreeMap;

use serde::Deserialize;

/// The shipped table, embedded at build time like the gateway's copy.
pub const HARNESS_KINDS_JSON: &str = include_str!("../../config/harness-kinds.json");

#[derive(Debug, Clone, Deserialize)]
pub struct Table {
    #[serde(default)]
    pub runtimes: BTreeMap<String, Runtime>,
    pub kinds: Vec<Kind>,
}

/// One row, the fields the CLI uses.
#[derive(Debug, Clone, Deserialize)]
pub struct Kind {
    pub kind: String,
    /// The vendor executable that must be on PATH on the node (`None` for `noo`).
    #[serde(default)]
    pub cli: Option<String>,
    /// Where the controller stages that executable from; `None` = manual install.
    #[serde(default)]
    pub distribution: Option<Distribution>,
}

/// What shape the vendor ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    /// An npm package tarball (`package/…`), run by a runtime.
    NpmTarball,
    /// An archive holding the CLI.
    Tarball,
    /// A single executable.
    Binary,
}

/// How the artefact is unpacked on the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum Unpack {
    #[serde(rename = "tgz")]
    Tgz,
    #[serde(rename = "tar.xz")]
    TarXz,
    #[serde(rename = "zip")]
    Zip,
    #[serde(rename = "none")]
    None,
}

impl Unpack {
    /// The manifest/applier spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Unpack::Tgz => "tgz",
            Unpack::TarXz => "tar.xz",
            Unpack::Zip => "zip",
            Unpack::None => "none",
        }
    }
    /// The extension of the cached artefact.
    pub fn ext(self) -> &'static str {
        match self {
            Unpack::None => "bin",
            u => u.as_str(),
        }
    }
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::NpmTarball => "npm-tarball",
            Format::Tarball => "tarball",
            Format::Binary => "binary",
        }
    }
}

/// noomesh platform facts → the vendor's spelling.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Names {
    #[serde(default)]
    pub os: BTreeMap<String, String>,
    #[serde(default)]
    pub arch: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Distribution {
    pub format: Format,
    pub source: String,
    #[serde(default)]
    pub names: Option<Names>,
    pub version: String,
    pub sha256: BTreeMap<String, String>,
    #[serde(default)]
    pub runtime: Option<String>,
    pub entry: String,
    pub unpack: Unpack,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Runtime {
    pub version: String,
    pub source: String,
    #[serde(default)]
    pub names: Option<Names>,
    pub sha256: BTreeMap<String, String>,
    pub unpack: Unpack,
    pub bin_dir: String,
}

/// The part of a pin `artifact_url` needs; both a distribution and a
/// runtime are one.
pub trait Pinned {
    fn source(&self) -> &str;
    fn names(&self) -> Option<&Names>;
    fn version(&self) -> &str;
    fn sha256(&self) -> &BTreeMap<String, String>;
    /// One artefact for every platform.
    fn is_any(&self) -> bool {
        self.sha256().contains_key("any")
    }
}

impl Pinned for Distribution {
    fn source(&self) -> &str { &self.source }
    fn names(&self) -> Option<&Names> { self.names.as_ref() }
    fn version(&self) -> &str { &self.version }
    fn sha256(&self) -> &BTreeMap<String, String> { &self.sha256 }
}

impl Pinned for Runtime {
    fn source(&self) -> &str { &self.source }
    fn names(&self) -> Option<&Names> { self.names.as_ref() }
    fn version(&self) -> &str { &self.version }
    fn sha256(&self) -> &BTreeMap<String, String> { &self.sha256 }
}

/// The platforms noomesh stages for.
pub const OSES: &[&str] = &["linux", "macos"];
pub const ARCHES: &[&str] = &["x86_64", "aarch64"];

/// A node's reported os/arch in noomesh's spelling (`darwin` → `macos`,
/// `amd64` → `x86_64`, `arm64` → `aarch64`); None for anything else.
pub fn normalize_platform(os: &str, arch: &str) -> Option<(&'static str, &'static str)> {
    let os = match os.trim().to_ascii_lowercase().as_str() {
        "linux" => "linux",
        "macos" | "darwin" | "osx" => "macos",
        _ => return None,
    };
    let arch = match arch.trim().to_ascii_lowercase().as_str() {
        "x86_64" | "amd64" | "x64" => "x86_64",
        "aarch64" | "arm64" => "aarch64",
        _ => return None,
    };
    Some((os, arch))
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The URL to fetch `p` from for `os`/`arch` (noomesh spelling) and the
/// sha256 it must hash to (lowercase hex). An `any` pin serves every
/// platform. Refused: no pin for the platform, a pin that is not 64 hex,
/// or a `names` map that does not spell this platform (the vendor ships
/// nothing for it).
pub fn artifact_url(p: &dyn Pinned, os: &str, arch: &str) -> Result<(String, String), String> {
    let platform = format!("{os}-{arch}");
    let sha = p
        .sha256()
        .get("any")
        .or_else(|| p.sha256().get(&platform))
        .ok_or_else(|| format!("no sha256 pin for {platform} (pinned: {})", p.sha256().keys().cloned().collect::<Vec<_>>().join(", ")))?;
    if !is_sha256_hex(sha) {
        return Err(format!("the sha256 pin for {platform} is not 64 hex characters ({sha:?})"));
    }
    let (vos, varch) = match p.names() {
        Some(n) => (
            n.os.get(os).cloned().ok_or_else(|| format!("names.os does not spell {os}: the vendor ships nothing for it"))?,
            n.arch.get(arch).cloned().ok_or_else(|| format!("names.arch does not spell {arch}: the vendor ships nothing for it"))?,
        ),
        None => (os.to_string(), arch.to_string()),
    };
    let url = p
        .source()
        .replace("{version}", p.version())
        .replace("{os}", &vos)
        .replace("{arch}", &varch);
    if !url.starts_with("https://") {
        return Err(format!("{url} is not an https URL"));
    }
    Ok((url, sha.to_ascii_lowercase()))
}

/// Parse a table (the shipped one, or a test fixture).
pub fn parse(raw: &str) -> Result<Table, String> {
    serde_json::from_str(raw).map_err(|e| format!("config/harness-kinds.json does not parse: {e}"))
}

/// The shipped table. Built in, so a parse failure is a build-time defect
/// the tests below catch; at run time it reads as an empty table.
pub fn shipped() -> Table {
    parse(HARNESS_KINDS_JSON).unwrap_or(Table { runtimes: BTreeMap::new(), kinds: Vec::new() })
}

/// The kind names, in declared order.
pub fn names() -> Vec<String> {
    shipped().kinds.into_iter().map(|k| k.kind).collect()
}

#[cfg(test)]
pub(crate) const FIXTURE: &str = r#"{
  "runtimes": {
    "node": { "version": "22.11.0",
              "source": "https://nodejs.org/dist/v{version}/node-v{version}-{os}-{arch}.tar.xz",
              "names": {"os": {"linux": "linux", "macos": "darwin"}, "arch": {"x86_64": "x64", "aarch64": "arm64"}},
              "sha256": {"linux-x86_64": "1111111111111111111111111111111111111111111111111111111111111111",
                         "linux-aarch64": "2222222222222222222222222222222222222222222222222222222222222222",
                         "macos-aarch64": "3333333333333333333333333333333333333333333333333333333333333333"},
              "unpack": "tar.xz", "bin_dir": "bin" } },
  "kinds": [
    { "kind": "noo", "cli": null, "title": "x", "extra": [1, 2] },
    { "kind": "copilot", "cli": "copilot",
      "distribution": { "format": "npm-tarball",
                        "source": "https://registry.npmjs.org/@github/copilot/-/copilot-{version}.tgz",
                        "names": null, "version": "0.0.339",
                        "sha256": {"any": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
                        "runtime": "node", "entry": "package/index.js", "unpack": "tgz" } },
    { "kind": "codex", "cli": "codex",
      "distribution": { "format": "binary",
                        "source": "https://example.invalid/codex/{version}/codex-{arch}-{os}",
                        "names": {"os": {"linux": "unknown-linux-musl", "macos": "apple-darwin"}, "arch": {"x86_64": "x86_64", "aarch64": "aarch64"}},
                        "version": "0.46.0",
                        "sha256": {"linux-x86_64": "4444444444444444444444444444444444444444444444444444444444444444",
                                   "macos-aarch64": "5555555555555555555555555555555555555555555555555555555555555555"},
                        "runtime": null, "entry": "codex", "unpack": "none" } },
    { "kind": "manual", "cli": "manualcli" },
    { "kind": "zipped", "cli": "zcli",
      "distribution": { "format": "tarball", "source": "https://example.invalid/z-{version}-{os}-{arch}.zip",
                        "version": "1.0.0", "sha256": {"linux-x86_64": "6666666666666666666666666666666666666666666666666666666666666666"},
                        "entry": "z/bin/zcli", "unpack": "zip" } }
  ]
}"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_table_parses_and_starts_with_noo() {
        let t = parse(HARNESS_KINDS_JSON).expect("shipped table");
        assert_eq!(t.kinds.first().map(|k| k.kind.as_str()), Some("noo"));
        assert!(names().iter().any(|k| k == "codex"));
    }

    #[test]
    fn every_variant_of_the_fixture_parses() {
        let t = parse(FIXTURE).unwrap();
        assert_eq!(t.runtimes["node"].unpack, Unpack::TarXz);
        assert_eq!(t.runtimes["node"].bin_dir, "bin");
        let by = |k: &str| t.kinds.iter().find(|r| r.kind == k).unwrap().clone();
        let cop = by("copilot").distribution.unwrap();
        assert_eq!((cop.format, cop.unpack, cop.runtime.as_deref()), (Format::NpmTarball, Unpack::Tgz, Some("node")));
        assert!(cop.names.is_none() && cop.is_any());
        let cx = by("codex").distribution.unwrap();
        assert_eq!((cx.format, cx.unpack, cx.runtime.as_deref()), (Format::Binary, Unpack::None, None));
        assert!(!cx.is_any());
        assert!(by("manual").distribution.is_none(), "a cli with no distribution is a manual install");
        assert_eq!(by("manual").cli.as_deref(), Some("manualcli"));
        let z = by("zipped").distribution.unwrap();
        assert_eq!((z.format, z.unpack), (Format::Tarball, Unpack::Zip));
        assert!(by("noo").cli.is_none());
    }

    #[test]
    fn a_table_without_runtimes_or_distributions_still_parses() {
        let t = parse(r#"{"kinds": [{"kind": "noo", "cli": null}, {"kind": "x", "cli": "x"}]}"#).unwrap();
        assert!(t.runtimes.is_empty());
        assert!(t.kinds.iter().all(|k| k.distribution.is_none()));
    }

    #[test]
    fn an_unknown_format_or_unpack_is_refused() {
        let bad = FIXTURE.replace(r#""unpack": "tgz""#, r#""unpack": "rar""#);
        assert!(parse(&bad).is_err());
        let bad = FIXTURE.replace(r#""format": "binary""#, r#""format": "dmg""#);
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn artifact_url_applies_names_and_the_platform_pin() {
        let t = parse(FIXTURE).unwrap();
        let node = &t.runtimes["node"];
        let (u, s) = artifact_url(node, "macos", "aarch64").unwrap();
        assert_eq!(u, "https://nodejs.org/dist/v22.11.0/node-v22.11.0-darwin-arm64.tar.xz");
        assert_eq!(s, "3".repeat(64));
        let (u, _) = artifact_url(node, "linux", "x86_64").unwrap();
        assert_eq!(u, "https://nodejs.org/dist/v22.11.0/node-v22.11.0-linux-x64.tar.xz");
        let e = artifact_url(node, "macos", "x86_64").unwrap_err();
        assert!(e.contains("no sha256 pin for macos-x86_64"), "{e}");

        let cx = t.kinds.iter().find(|k| k.kind == "codex").unwrap().distribution.clone().unwrap();
        let (u, s) = artifact_url(&cx, "linux", "x86_64").unwrap();
        assert_eq!(u, "https://example.invalid/codex/0.46.0/codex-x86_64-unknown-linux-musl");
        assert_eq!(s, "4".repeat(64));
    }

    #[test]
    fn an_any_pin_serves_every_platform_lowercased_and_without_names() {
        let t = parse(FIXTURE).unwrap();
        let cop = t.kinds.iter().find(|k| k.kind == "copilot").unwrap().distribution.clone().unwrap();
        for os in OSES {
            for arch in ARCHES {
                let (u, s) = artifact_url(&cop, os, arch).unwrap();
                assert_eq!(u, "https://registry.npmjs.org/@github/copilot/-/copilot-0.0.339.tgz");
                assert_eq!(s, "a".repeat(64));
            }
        }
    }

    #[test]
    fn a_names_map_that_does_not_spell_the_platform_is_refused() {
        let mut t = parse(FIXTURE).unwrap();
        let node = t.runtimes.get_mut("node").unwrap();
        node.names.as_mut().unwrap().os.remove("macos");
        let e = artifact_url(node, "macos", "aarch64").unwrap_err();
        assert!(e.contains("names.os does not spell macos"), "{e}");
    }

    #[test]
    fn a_malformed_pin_or_plain_http_is_refused() {
        let mut t = parse(FIXTURE).unwrap();
        let node = t.runtimes.get_mut("node").unwrap();
        node.sha256.insert("linux-x86_64".into(), "abc".into());
        assert!(artifact_url(node, "linux", "x86_64").unwrap_err().contains("not 64 hex"));
        node.sha256.insert("linux-x86_64".into(), "1".repeat(64));
        node.source = node.source.replace("https://", "http://");
        assert!(artifact_url(node, "linux", "x86_64").unwrap_err().contains("not an https URL"));
    }

    #[test]
    fn platforms_normalize_from_every_reported_spelling() {
        assert_eq!(normalize_platform("darwin", "arm64"), Some(("macos", "aarch64")));
        assert_eq!(normalize_platform("linux", "amd64"), Some(("linux", "x86_64")));
        assert_eq!(normalize_platform("macos", "aarch64"), Some(("macos", "aarch64")));
        assert_eq!(normalize_platform("windows", "x86_64"), None);
        assert_eq!(normalize_platform("linux", "riscv64"), None);
    }
}
