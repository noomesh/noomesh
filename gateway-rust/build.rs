// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Build script: detect optional pro-only sources.
//!
//! routes/pro.rs and its `has_pro_routes` cfg retired —
//! the evolve routes are an OSS-safe always-compiled proxy
//! (routes/evolve_proxy.rs) with a runtime add-on gate (addons.rs).

fn main() {
    // Declare the custom cfgs so the unexpected_cfgs lint stays quiet on
    // toolchains that enforce check-cfg (Rust 1.80+).
    println!("cargo::rustc-check-cfg=cfg(has_pro_baseline)");

    let _manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    // migrations/0002_pro.sql is the PRO half of the mesh schema baseline,
    // also stripped by the OSS sync. Same shape as above: mesh_migrate.rs
    // `include_str!`s it only under this cfg, so an OSS checkout compiles.
    //
    // This is deliberately a BUILD-time predicate, not the NOO_PRO_ENABLED
    // env var. Alembic's equivalent (001_baseline's create_all) creates the
    // pro tables whenever models_pro is importable — presence of code, not a
    // runtime flag. Gating on the env var instead would give a pro build with
    // the flag off a 44-table schema where Alembic produced 49, and enabling
    // pro later would never create them, because the baseline only ever runs
    // on an empty database.
    // has_pro_baseline is GONE. The mesh baseline is
    // OSS-only by construction now — evolve's five tables come from evolve's
    // own chain, into its own schema — so there is no pro SQL to probe for
    // and no cfg to set. The check-cfg registration below stays until the
    // last #[cfg(has_pro_baseline)] leaves the tree, so a stale branch
    // rebasing across this change gets a real error instead of a silent
    // never-compiled block.
}
