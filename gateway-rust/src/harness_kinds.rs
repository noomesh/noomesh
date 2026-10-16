// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The harness kinds a harness placement may name in `NOO_HARNESS_KIND`,
//! declared ONCE in `config/harness-kinds.json` and embedded here at compile
//! time. The node agent embeds a copy of the same file (held equal by its
//! `TestHarnessKindsTableMatchesTheShippedFile`), so adding a kind is one
//! edit to that file plus the copy, not a constant in each binary.
//!
//! The path is a literal `../../config/...` rather than
//! `concat!(env!("CARGO_MANIFEST_DIR"), ...)` so
//! `tests/test_rust_build_context_complete.py` sees it and holds the Docker
//! builder stage's COPY list to it.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use serde::Deserialize;

const RAW: &str = include_str!("../../config/harness-kinds.json");

/// One row of the table.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // the gateway validates by name; the other fields are the node agent's
pub struct HarnessKind {
    pub kind: String,
    pub title: String,
    /// The API the harness speaks.
    pub wire: String,
    /// Node chat backend types that serve that wire (empty: none yet).
    pub wires: Vec<String>,
    /// The executable the applier installs beside the agent; `None` = no
    /// runner ships yet, and the node agent refuses the kind.
    pub runner: Option<String>,
    /// The vendor executable that must be on PATH on the node (`None` for `noo`).
    pub cli: Option<String>,
    /// Env vars that keep the CLI one-shot and inside its lane.
    pub lane: BTreeMap<String, String>,
    /// How the driver invokes the CLI (`None` for `noo`).
    pub launch: Option<Launch>,
    /// Vendor telemetry switches the runner must launch it with.
    pub telemetry_off: BTreeMap<String, String>,
    /// Where the controller stages the vendor CLI from (i83 E1e); `None` =
    /// a manual install, or no CLI at all.
    #[serde(default)]
    pub distribution: Option<Distribution>,
}

/// noomesh platform facts (`linux`/`macos`, `x86_64`/`aarch64`) → the
/// vendor's spelling inside a `source` URL template.
#[derive(Debug, Clone, Default, Deserialize)]
#[allow(dead_code)]
pub struct Names {
    #[serde(default)]
    pub os: BTreeMap<String, String>,
    #[serde(default)]
    pub arch: BTreeMap<String, String>,
}

/// What shape a vendor ships its CLI in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)]
pub enum Format {
    Tarball,
    Binary,
}

/// How the artefact is unpacked on the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[allow(dead_code)]
pub enum Unpack {
    #[serde(rename = "tgz")]
    Tgz,
    #[serde(rename = "zip")]
    Zip,
    #[serde(rename = "none")]
    None,
}

/// A kind's staged vendor CLI: the controller fetches `source` (with
/// `{version}`, `{os}`, `{arch}` filled in through `names`), verifies it
/// against `sha256` (`any`, or keyed `<os>-<arch>`), and ships it to the
/// node over the rail. `noo cluster vendor stage` is the fetch; the node
/// never fetches.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct Distribution {
    pub format: Format,
    pub source: String,
    #[serde(default)]
    pub names: Option<Names>,
    pub version: String,
    pub sha256: BTreeMap<String, String>,
    /// The path inside the unpacked tree to execute.
    pub entry: String,
    pub unpack: Unpack,
}

/// The URL to fetch an artefact from for `os`/`arch` and the sha256 it
/// must hash to (lowercase). The noo CLI's `harness_kinds::artifact_url`
/// is the same rule; this copy keeps the gateway's reading of the table
/// typed and tested.
#[allow(dead_code)]
pub fn artifact_url(
    source: &str,
    names: Option<&Names>,
    version: &str,
    sha256: &BTreeMap<String, String>,
    os: &str,
    arch: &str,
) -> Result<(String, String), String> {
    let platform = format!("{os}-{arch}");
    let sha = sha256
        .get("any")
        .or_else(|| sha256.get(&platform))
        .ok_or_else(|| format!("no sha256 pin for {platform}"))?;
    if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("the sha256 pin for {platform} is not 64 hex characters"));
    }
    let (vos, varch) = match names {
        Some(n) => (
            n.os.get(os).cloned().ok_or_else(|| format!("names.os does not spell {os}"))?,
            n.arch.get(arch).cloned().ok_or_else(|| format!("names.arch does not spell {arch}"))?,
        ),
        None => (os.to_string(), arch.to_string()),
    };
    let url = source.replace("{version}", version).replace("{os}", &vos).replace("{arch}", &varch);
    Ok((url, sha.to_ascii_lowercase()))
}

/// How the driver (`harness::driver`) invokes a foreign CLI. A value
/// starting `unverified:` is documented-but-unconfirmed, and the driver
/// refuses a kind that still carries one.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct Launch {
    /// argv; `{prompt}` and `{mcp_config}` (the MCP config file the driver
    /// writes) are filled in by the driver, inside any argument.
    pub command: Vec<String>,
    /// The variable that points the CLI at the loopback translator (empty
    /// when the config file the driver writes carries the URL).
    pub model_url_env: String,
    /// The variable that names the CLI's model (empty likewise).
    pub model_env: String,
    /// How the CLI takes an MCP server. `config-file`: the driver writes
    /// `{"mcpServers": {"noomesh": {...}}}` and passes its path as
    /// `{mcp_config}` in `command`. `config-file:codex-toml`: the driver
    /// writes Codex's whole `config.toml` under `home_env` (model provider,
    /// model, MCP server, approvals, sandbox, telemetry off).
    pub mcp: String,
    /// Appended to the translator's base URL (`/v1` for a CLI that appends
    /// `/chat/completions` to the URL it is given).
    #[serde(default)]
    pub model_url_suffix: String,
    /// A variable the CLI insists on before it calls a provider; the driver
    /// fills it with a placeholder, the loopback translator takes no key.
    #[serde(default)]
    pub api_key_env: Option<String>,
    /// More variables that name a model (a CLI's background/sub-agent
    /// models); all set to the pinned model, so nothing asks for one the
    /// node does not serve.
    #[serde(default)]
    pub model_alias_envs: Vec<String>,
    /// The variable naming the CLI's config/state directory; the driver
    /// points it inside the task's own HOME.
    #[serde(default)]
    pub home_env: Option<String>,
    /// A variable that names a CA bundle file for this CLI (beside
    /// `NODE_EXTRA_CA_CERTS`, which every driven CLI gets); the driver sets
    /// it to the cluster CA so the CLI can reach the user door.
    #[serde(default)]
    pub ca_env: Option<String>,
}

#[derive(Deserialize)]
struct Table {
    kinds: Vec<HarnessKind>,
}

static KINDS: LazyLock<Vec<HarnessKind>> = LazyLock::new(|| {
    serde_json::from_str::<Table>(RAW)
        .expect("config/harness-kinds.json is malformed")
        .kinds
});

/// Every declared kind, in declared order (`noo` first).
#[allow(dead_code)]
pub fn all() -> &'static [HarnessKind] {
    &KINDS
}

/// One kind by name.
pub fn get(kind: &str) -> Option<&'static HarnessKind> {
    KINDS.iter().find(|k| k.kind == kind)
}

/// The kind names, in declared order.
pub fn names() -> Vec<&'static str> {
    KINDS.iter().map(|k| k.kind.as_str()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn the_shipped_table_parses() {
        let t: Table = serde_json::from_str(RAW).expect("config/harness-kinds.json parses");
        assert!(!t.kinds.is_empty(), "no kinds declared");
        assert_eq!(all().len(), t.kinds.len());
    }

    #[test]
    fn noo_is_first_and_has_a_runner() {
        let first = &all()[0];
        assert_eq!(first.kind, "noo");
        assert_eq!(first.runner.as_deref(), Some("noo-gateway"));
    }

    #[test]
    fn every_kind_declares_its_telemetry_switches() {
        // The map may be empty; the KEY may not be absent (serde would
        // reject the row), and a raw-JSON look makes that explicit.
        let v: serde_json::Value = serde_json::from_str(RAW).unwrap();
        for k in v["kinds"].as_array().unwrap() {
            assert!(k.get("telemetry_off").is_some_and(|t| t.is_object()), "{} has no telemetry_off object", k["kind"]);
        }
    }

    #[test]
    fn one_runner_for_every_kind() {
        for k in all() {
            assert_eq!(k.runner.as_deref(), Some("noo-gateway"), "{} runner", k.kind);
        }
    }

    #[test]
    fn foreign_kinds_carry_a_cli_and_a_launch_recipe() {
        for k in all() {
            if k.kind == "noo" {
                assert!(k.cli.is_none() && k.launch.is_none(), "noo has no vendor CLI");
                continue;
            }
            let cli = k.cli.as_deref().unwrap_or_else(|| panic!("{} has no cli", k.kind));
            let l = k.launch.as_ref().unwrap_or_else(|| panic!("{} has no launch", k.kind));
            assert!(!l.command.is_empty(), "{} launch.command empty", k.kind);
            assert_eq!(l.command[0], cli, "{} launch.command[0] must be its cli", k.kind);
        }
    }

    /// Every foreign kind runs on every node backend through the loopback
    /// translator, and no shipped launch recipe is still `unverified:`.
    #[test]
    fn foreign_kinds_are_served_by_every_backend_and_verified() {
        for k in all().iter().filter(|k| k.kind != "noo") {
            assert_eq!(k.wires, ["vllm", "vllm-secondary", "llamacpp", "ollama", "airllm"], "{} wires", k.kind);
            let l = k.launch.as_ref().unwrap();
            let mut fields = vec![&l.model_url_env, &l.model_env, &l.mcp];
            fields.extend(l.command.iter());
            assert!(!fields.iter().any(|v| v.starts_with("unverified:")), "{} launch is unverified: {fields:?}", k.kind);
        }
    }

    #[test]
    fn kinds_are_unique() {
        let mut seen = HashSet::new();
        for n in names() {
            assert!(!n.is_empty(), "an empty kind");
            assert!(seen.insert(n), "kind {n} declared twice");
        }
    }

    /// The pinned vendor artefacts (`distribution`) rides in the
    /// same file. `HarnessKind` has no field for them yet and serde ignores
    /// unknown fields (no `deny_unknown_fields`), so the typed table still
    /// parses; this looks at the raw JSON so a foreign kind cannot ship
    /// without the artefact the controller stages for it.
    #[test]
    fn foreign_kinds_carry_a_pinned_distribution() {
        let _ = all(); // the typed parse tolerates the new fields
        let v: serde_json::Value = serde_json::from_str(RAW).unwrap();
        let hex64 = |s: &serde_json::Value| s.as_str().is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        for k in v["kinds"].as_array().unwrap() {
            let d = k.get("distribution").unwrap_or_else(|| panic!("{} has no distribution key", k["kind"]));
            if k["cli"].is_null() {
                assert!(d.is_null(), "{} has no CLI, so no distribution", k["kind"]);
                continue;
            }
            assert!(d.is_object(), "{} launches a CLI but has no distribution", k["kind"]);
            assert!(d["version"].as_str().is_some_and(|s| !s.is_empty()), "{} distribution.version", k["kind"]);
            let sha = d["sha256"].as_object().unwrap_or_else(|| panic!("{} distribution.sha256", k["kind"]));
            let keys: Vec<&str> = if sha.contains_key("any") { vec!["any"] } else { vec!["linux-x86_64", "linux-aarch64", "macos-aarch64"] };
            for p in keys {
                assert!(sha.get(p).is_some_and(hex64), "{} sha256[{p}]", k["kind"]);
            }
        }
    }

    const FIXTURE: &str = r#"{
      "kinds": [
        {"kind": "noo", "title": "t", "wire": "w", "wires": [], "runner": "noo-gateway", "cli": null,
         "lane": {}, "launch": null, "telemetry_off": {}},
        {"kind": "copilot", "title": "t", "wire": "w", "wires": [], "runner": "noo-gateway", "cli": "copilot",
         "lane": {}, "launch": null, "telemetry_off": {},
         "distribution": {"format": "tarball", "source": "https://example.invalid/copilot/{version}/copilot.tgz",
           "names": null, "version": "0.0.339",
           "sha256": {"any": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
           "entry": "bin/copilot", "unpack": "tgz"}},
        {"kind": "codex", "title": "t", "wire": "w", "wires": [], "runner": "noo-gateway", "cli": "codex",
         "lane": {}, "launch": null, "telemetry_off": {},
         "distribution": {"format": "binary", "source": "https://example.invalid/{version}/codex-{arch}-{os}",
           "names": {"os": {"linux": "unknown-linux-musl"}, "arch": {"x86_64": "x86_64"}}, "version": "0.46.0",
           "sha256": {"linux-x86_64": "4444444444444444444444444444444444444444444444444444444444444444"},
           "entry": "codex", "unpack": "none"}},
        {"kind": "manual", "title": "t", "wire": "w", "wires": [], "runner": "noo-gateway", "cli": "m",
         "lane": {}, "launch": null, "telemetry_off": {}}
      ]}"#;

    #[test]
    fn the_distribution_fixture_parses_every_variant() {
        let t: Table = serde_json::from_str(FIXTURE).expect("fixture parses");
        let d = |k: &str| t.kinds.iter().find(|r| r.kind == k).unwrap().distribution.clone();
        let cop = d("copilot").unwrap();
        assert_eq!((cop.format, cop.unpack), (Format::Tarball, Unpack::Tgz));
        let cx = d("codex").unwrap();
        assert_eq!((cx.format, cx.unpack), (Format::Binary, Unpack::None));
        assert!(d("manual").is_none(), "a cli with no distribution is a manual install");
        assert!(d("noo").is_none());
    }

    #[test]
    fn artifact_url_applies_names_and_pins() {
        let t: Table = serde_json::from_str(FIXTURE).unwrap();
        let cop = t.kinds.iter().find(|r| r.kind == "copilot").unwrap().distribution.clone().unwrap();
        let (u, s) = artifact_url(&cop.source, cop.names.as_ref(), &cop.version, &cop.sha256, "linux", "aarch64").unwrap();
        assert_eq!(u, "https://example.invalid/copilot/0.0.339/copilot.tgz");
        assert_eq!(s, "a".repeat(64), "an any pin serves every platform, lowercased");
        let cx = t.kinds.iter().find(|r| r.kind == "codex").unwrap().distribution.clone().unwrap();
        let (u, _) = artifact_url(&cx.source, cx.names.as_ref(), &cx.version, &cx.sha256, "linux", "x86_64").unwrap();
        assert_eq!(u, "https://example.invalid/0.46.0/codex-x86_64-unknown-linux-musl");
        assert!(artifact_url(&cx.source, cx.names.as_ref(), &cx.version, &cx.sha256, "linux", "aarch64").is_err(), "no pin for the platform");
    }

    #[test]
    fn the_shipped_table_parses_with_or_without_distributions() {
        // The shipped file may or may not carry the E1e data yet; either way
        // every declared distribution must parse into the typed shape.
        let t: Table = serde_json::from_str(RAW).expect("parses");
        for k in &t.kinds {
            if k.distribution.is_some() {
                assert!(k.cli.is_some(), "{} has a distribution but no cli", k.kind);
            }
        }
    }

    #[test]
    fn the_validation_message_lists_the_table() {
        assert_eq!(names().join(", "), "noo, claude-code, copilot, codex");
    }
}
