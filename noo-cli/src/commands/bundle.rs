// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo bundle export <out.tar.gz>` — write this binary's embedded standalone
//! deploy slice as a versioned bundle (fu67 Mode B's producer half).
//!
//! Single source of truth: the bundle is generated FROM the embedded asset
//! table, so there is no second manifest to drift — any released binary can
//! produce the bundle matching its own version. The release workflow runs
//! this on the built amd64 binary and attaches the result, giving
//! `noo onboard --standalone --bundle <release-url>` a verifiable artifact
//! (a `.sha256` sidecar is written next to the output).

use crate::output::{fail, ExitCode};
use crate::{Globals, Unhandled};
use crate::ui;
use sha2::{Digest, Sha256};

pub fn bundle_export(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let out = match args {
        [one] if !one.starts_with('-') => one.clone(),
        _ => fail(g.json, ExitCode::Usage, "usage", "output path required",
            Some("usage: noo bundle export <out.tar.gz>")),
    };
    if !out.ends_with(".tar.gz") && !out.ends_with(".tgz") {
        fail(g.json, ExitCode::Usage, "usage",
            "output must end in .tar.gz or .tgz", None);
    }

    // Stage the assets in a temp tree, tar it up. write_assets carries the
    // empty-table refusal (crate-only builds have nothing to export).
    let stage = std::env::temp_dir().join(format!("noo-bundle-export-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&stage);
    if let Err(e) = crate::onboard::standalone::write_assets(&stage) {
        let _ = std::fs::remove_dir_all(&stage);
        fail(g.json, ExitCode::Generic, "no_assets", &e.to_string(), None);
    }
    let ok = std::process::Command::new("tar")
        .arg("-czf").arg(&out).arg("-C").arg(&stage).arg(".")
        .status().map(|s| s.success()).unwrap_or(false);
    let _ = std::fs::remove_dir_all(&stage);
    if !ok {
        fail(g.json, ExitCode::Generic, "tar_failed", "tar -czf failed", None);
    }

    // .sha256 sidecar in the exact `<hex>  <basename>` shape install.sh and
    // the bundle consumer verify.
    let bytes = match std::fs::read(&out) {
        Ok(b) => b,
        Err(e) => fail(g.json, ExitCode::Generic, "read_failed",
            &format!("cannot read back {out}: {e}"), None),
    };
    let digest = {
        let mut h = Sha256::new();
        h.update(&bytes);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let base = std::path::Path::new(&out).file_name()
        .map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| out.clone());
    if let Err(e) = std::fs::write(format!("{out}.sha256"), format!("{digest}  {base}\n")) {
        fail(g.json, ExitCode::Generic, "sidecar_failed",
            &format!("cannot write {out}.sha256: {e}"), None);
    }

    let n = crate::onboard::standalone::asset_count();
    if g.json {
        println!("{}", serde_json::json!({
            "status":"exported","bundle":out,"assets":n,"sha256":digest,
            "version": env!("CARGO_PKG_VERSION"),
        }));
    } else {
        ui::done(&format!("exported {n} assets to {out} (+ .sha256)"));
        ui::value(&out);
        let onboard = format!("noo onboard --standalone --bundle {out}");
        ui::guide(&[(onboard.as_str(), "on the target box: bootstraps a controller from this bundle with no network fetch")]);
    }
    Ok(0)
}
