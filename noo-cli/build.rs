// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Build script: (1) bake the standalone-controller deploy slice into the
//! binary, and (2) derive the add-on declarations from the overlays.
//! (There is no pro-only command module any more: add-ons bring their own
//! `noo` commands at runtime, commands/addon_cli.rs.)
//!
//! (1) `pai onboard --standalone` needs the compose files, config templates,
//! and launch-script chain WITHOUT a repo checkout. We generate a table of
//! `include_bytes!` entries — the ACTUAL repo files, so there is no copy to
//! drift and a missing file fails the build (the mcp-tools.json lesson). The
//! table is (dest-relpath, bytes, is_executable); `onboard::standalone`
//! materialises it under ~/.pai.
//!
//! (2) Each add-on overlay's top-level `x-noo-addon` block
//! becomes `ADDON_DECLS` + `ADDON_KEY_SPECS` in `addon_decls.rs`:
//! the secret registry's add-on rows and each add-on's default grant are
//! DERIVED from the overlay, not written a second time in secrets.rs. A
//! malformed block fails the build, not a provision.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn main() {
    // The licence signer is a separate source file that is not in every
    // tree. The cfg is set only when the file exists; without it the
    // `keygen` and `issue` verbs answer "not available in this build".
    println!("cargo::rustc-check-cfg=cfg(has_entitlement_signer)");
    println!("cargo::rerun-if-changed=src/commands/entitlement_signer.rs");
    if Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands/entitlement_signer.rs").exists() {
        println!("cargo::rustc-cfg=has_entitlement_signer");
    }
    gen_standalone_assets();
}

/// Individual files: (repo-relative source, dest-relpath under ~/.pai).
/// The `.sh` heuristic marks scripts executable at materialise time.
const STANDALONE_FILES: &[&str] = &[
    "docker-compose.cluster.yml",
    "docker-compose.dist.yml",
    // docker-compose.pro.yml left the tree with an earlier release (evolve as a
    // runtime extension — zero pro files in-tree, dece27e); the manifest
    // entry outlived the file and broke every repo-tree build.
    "noomesh.yaml.example",
    "docker-compose.gpu-embed.yml",
    // This list is an allowlist, so an overlay added to the tree but not
    // here never reaches a dist install (stack-v0.2.47, 2026-09-14); the
    // slice test pins every root overlay to this list. Licensed add-ons'
    // overlays are NOT here: each travels in its add-on's signed bundle and
    // is materialised under <install root>/addons/<name>/ (N6).
    // The knowledge pack as an overlay.
    "docker-compose.trellion.yml",
    // Voice (whisper + piper) as an overlay.
    "docker-compose.voice.yml",
    "config/tailscale-acl.hujson",
    "scripts/noomesh-start.sh",
    // `pai stack restart` runs this (mesh.rs) — was missing, so day-2
    // restart on a standalone box would have failed (finding #28's sweep).
    "scripts/noomesh-restart.sh",
    "scripts/lib-bind-addr.sh",
    // Sourced by both launchers since PR #813 (Created-wedge self-heal);
    // its absence broke the first otherwise-smooth onboard at the LAUNCH
    // line (finding #28). The embedded_launchers_have_their_libs test now
    // pins the class: every lib a launcher sources must be embedded.
    "scripts/lib-created-guard.sh",
    // `docker compose up` isolates one unkillable container (exit 75).
    "scripts/lib-stuck-container.sh",
    // Every launcher `compose up` is preceded by its bind-source check
    // (2026-09-29, grafana.pub made a directory by Docker).
    "scripts/lib-bind-sources.sh",
    // The launcher re-owns redis/grafana data to 65532 right before `up`.
    "scripts/lib-reown.sh",
    "scripts/lib-compose-lock.sh",
    "scripts/lib-addons.sh",
    // The retired-.env-key list: read by lib-addons.sh (the WARN) and by
    // `noo onboard --only env` (the removal offer).
    "scripts/retired-env-keys",
    "scripts/lib-config.sh",
    "scripts/lib-instance.sh",
    "scripts/lib-secrets.sh",
    "scripts/lib-dist.sh",
    // The compose file list has one home; every
    // launcher sources it, so a standalone install must ship it.
    "scripts/lib-compose.sh",
    // Name resolution + compose exit status for `noo stack restart <name>`.
    "scripts/lib-restart.sh",
    // Every launcher sources this for its glyphs/colours; it was NOT
    // embedded, so a standalone install had none of them (host8,
    // 2026-09-03). The launcher-lib guard test never caught it: the
    // noo-cli CI job builds the crate outside the repo tree, where
    // STANDALONE_ASSETS is empty and the test returns early. The
    // Python parity test now pins this class from the repo side.
    "scripts/lib-ui.sh",
    "scripts/sign-bundle.sh",
    "scripts/noo-secrets-sops-init.sh",
    // EVERY script a native verb invokes must be embedded (finding #28's
    // class, rediscovered 2026-09-01 on the host8 standalone controller:
    // the state-home-first root resolution in v0.3.7 stopped dev clones
    // from masking these — `noo stack stop/status/clean/logs/reset/rebuild`,
    // `stack sandbox`, `models convert` and `security secrets absorb-files`
    // all failed with "script not found" on a standalone box). The
    // embedded_cli_scripts_are_complete test pins the full set.
    "scripts/noo-model-convert.sh",
    "scripts/noo-secrets-absorb-files.sh",
    "scripts/noomesh-clean.sh",
    "scripts/noomesh-logs.sh",
    "scripts/noomesh-rebuild.sh",
    // Host-spool targets (host8 2026-09-02: the database_backup
    // heartbeat failed with "backup-controller.sh: No such file" — the
    // spool executor, now noo-hostd, runs it from the deploy slice, which
    // never carried it).
    "scripts/backup-controller.sh",
    "scripts/restore-drill.sh",
    "scripts/noo-backup-rotate-passphrase.sh",
    // `noo backups setup` offers `portable` and then tells the operator to
    // run this. A standalone controller has no checkout, so without it here
    // the one option that exists FOR a box with nowhere to copy to names a
    // file that box does not have.
    "scripts/noo-backup-export.sh",
    // `noo cluster set-primary` / `controller claim` tell the operator to run
    // this on the target box; a standalone box needs the file the text names.
    "scripts/bootstrap-standby.sh",
    "scripts/noomesh-reset.sh",
    "scripts/noomesh-sandbox.sh",
    "scripts/noomesh-status.sh",
    "scripts/noomesh-stop.sh",
    // Caught by the parity test itself on its first run — the tenth one.
    "scripts/verify-privilege-plane.sh",
    // `noo cluster provision` renders the agent env from the real
    // template and stages the unit — a standalone controller needs both.
    "node-agent-go/deploy/noo-node-agent.env.tmpl",
    "node-agent-go/deploy/noo-node-agent.service",
    // The harness pair is read the same way, from
    // the same directory, by the same function — and was missed for three
    // releases because its neighbour above was listed. host8 2026-09-19:
    // `noo upgrade --nodes` failed on all four non-controller nodes with
    // "cannot read the harness env template". The controller's own node
    // skips the harness block, so the node an operator watches most
    // closely was the one that could not fail.
    "node-agent-go/deploy/noo-harness.env.tmpl",
    "node-agent-go/deploy/noo-harness.service",
    // model-cache (standalone profile) + stunnel confs mount these.
    "docker/model-cache.nginx.conf",
    "docker/model-cache.locations.conf",
    "docker/stunnel-llamacpp.conf",
    "docker/stunnel-ollama.conf",
    // The standalone profile's embedder sidecar mounts this on EVERY
    // standalone install (not an opt-in profile like the rest).
    "docker/stunnel-ollama-embed.conf",
    "docker/stunnel-ollama-embed-cpu.conf",
    "docker/stunnel-reranker.conf",
    "docker/stunnel-tei-gpu.conf",
    "docker/stunnel-tei.conf",
    // The sandbox's seccomp profile (security_opt, derived by
    // scripts/derive-sandbox-seccomp.py). Docker opens it on the HOST at
    // create time, so a slice without it fails the whole `compose up`
    // before any container is recreated — the v0.2.33 roll on a standalone
    // controller died on exactly this (2026-09-10). Every host-side file a
    // compose service mounts or names must be listed here;
    // tests/test_standalone_slice_ships_compose_host_files.py pins this
    // list against the compose files so the next one cannot slip.
    "docker/seccomp-sandbox.json",
    // The sandbox's AppArmor profile for Ubuntu 24.04+ hosts (docker-default
    // plus the user-namespace and mount rules Bubblewrap needs). Not mounted
    // by compose: the operator installs it into /etc/apparmor.d once, so a
    // --dist controller must have the file to install.
    "docker/apparmor-noo-sandbox",
    // Redis reads its password from the environment through this script
    // instead of from a compose `command:` line, so a --dist
    // controller needs the script or redis will not start at all.
    "docker/redis-entrypoint.sh",
    // The Postgres client-auth policy the compose file mounts (TLS +
    // cluster-CA client cert on every TCP connection); the service refuses
    // to start without it, so a standalone install must ship it.
    "docker/postgres/pg_hba.conf",
];

/// Whole directories embedded recursively (all files). `monitoring/` and
/// `configs/grafana/` are the monitoring set every install runs;
/// `monitoring/nats/` is required by nats itself (it mounts nats-tls.conf).
const STANDALONE_DIRS: &[&str] = &["prompts", "skills", "monitoring", "configs/grafana"];

fn gen_standalone_assets() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().expect("noo-cli has a parent dir").to_path_buf();

    // The crate must also build OUT of the repo tree — CI's noo-cli and
    // standalone-smoke jobs mount ONLY noo-cli/ (cargo-docker.sh), so the
    // parent is bare. Those builds get an EMPTY asset table (and a loud
    // warning); `pai onboard --standalone` in such a binary fails with a
    // clear message. RELEASE builds must never take this branch — the
    // release workflow greps the built binaries for the sentinel asset
    // below, so a crate-only release build fails the workflow instead of
    // shipping a standalone-less default binary.
    // The stack tag this CLI is PAIRED with — what a no-repo standalone
    // controller runs, since it cannot `git tag` its way to one (the dist
    // launcher's normal resolution). Precedence: $NOO_STACK_TAG (the release
    // workflow sets it from the newest stack-v* tag before building) → local
    // `git tag` (dev builds from a checkout) → empty (crate-only CI builds;
    // onboard then requires the operator to set NOO_IMAGE_TAG).
    let stack_tag = std::env::var("NOO_STACK_TAG").ok()
        .map(|s| s.trim().trim_start_matches("stack-").to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let out = std::process::Command::new("git")
                .args(["-C", repo_root.to_str().unwrap_or("."), "tag", "-l", "stack-v*"])
                .output().ok()?;
            let mut tags: Vec<String> = String::from_utf8_lossy(&out.stdout)
                .lines().map(str::to_string).collect();
            tags.sort_by_key(|t| {
                t.trim_start_matches("stack-v").split('.')
                    .map(|p| p.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>()
            });
            tags.last().map(|t| t.trim_start_matches("stack-").to_string())
        })
        .unwrap_or_default();
    println!("cargo::rerun-if-env-changed=NOO_STACK_TAG");
    let tag_line = format!(
        "pub static STANDALONE_STACK_TAG: &str = {stack_tag:?};\n");

    if !repo_root.join("docker-compose.cluster.yml").exists() {
        println!("cargo::warning=noo-cli built OUTSIDE the repo tree — \
                  standalone assets NOT embedded (onboard --standalone will refuse)");
        let dest = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("standalone_assets.rs");
        std::fs::write(&dest, format!(
            "// @generated — crate-only build: no repo tree, no embedded assets.\n\
             pub static STANDALONE_ASSETS: &[(&str, &[u8], bool)] = &[];\n{tag_line}"))
            .expect("write standalone_assets.rs");
        write_enroll_assets(None);
        gen_addon_decls(None);
        return;
    }

    let mut entries: Vec<(String, PathBuf)> = Vec::new(); // (dest-relpath, abs-src)
    for f in STANDALONE_FILES {
        entries.push((f.to_string(), repo_root.join(f)));
    }
    for d in STANDALONE_DIRS {
        collect_dir(&repo_root, &repo_root.join(d), &mut entries);
    }

    let mut out = String::new();
    out.push_str("// @generated by build.rs — standalone-controller assets.\n");
    out.push_str("pub static STANDALONE_ASSETS: &[(&str, &[u8], bool)] = &[\n");
    // Sentinel FIRST: a greppable literal that exists in the binary only when
    // assets were embedded — the release workflow asserts on it.
    out.push_str("    (\".noo-embed-sentinel\", b\"NOO_EMBEDDED_ASSETS_PRESENT\", false),\n");
    for (dest, abs) in &entries {
        println!("cargo::rerun-if-changed={}", abs.display());
        let exec = dest.ends_with(".sh");
        // dest relpaths are our own literals / walked filenames — no quotes.
        // abs paths from the repo likewise; assert to fail loud if that breaks.
        assert!(!dest.contains('"') && !abs.to_string_lossy().contains('"'),
            "unexpected quote in asset path: {dest}");
        writeln!(out, "    ({dest:?}, include_bytes!({:?}), {exec}),",
            abs.to_string_lossy()).unwrap();
    }
    out.push_str("];\n");
    out.push_str(&tag_line);

    let dest = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("standalone_assets.rs");
    std::fs::write(&dest, out).expect("write standalone_assets.rs");
    write_enroll_assets(Some(&repo_root));
    gen_addon_decls(Some(&repo_root));
}

// The `x-noo-addon` parser, shared with the CLI's run-time reader of an
// add-on's bundled overlay (commands/secrets.rs `addon_decls`).
#[path = "src/addon_decl_parse.rs"]
#[allow(dead_code)]
mod addon_decl_parse;

/// One overlay's `x-noo-addon`, validated, with the file it came from.
struct Decl {
    overlay: String,
    addon: String,
    consumer: String,
    key: String,
    containers: Vec<String>,
    scopes: Vec<String>,
    why: Option<String>,
}

fn decl_of(overlay: &str, text: &str) -> Option<Decl> {
    // Same fact as lib-addons.sh's file mapping: addon `trellion` is
    // docker-compose.trellion.yml.
    let expect = addon_decl_parse::addon_of_overlay_name(overlay);
    let d = addon_decl_parse::parse_decl(overlay, text, expect.as_deref()).unwrap_or_else(|e| panic!("{e}"))?;
    Some(Decl {
        overlay: overlay.to_string(),
        addon: d.addon,
        consumer: d.consumer,
        key: d.key,
        containers: d.containers,
        scopes: d.scopes,
        why: d.why,
    })
}

/// `$OUT_DIR/addon_decls.rs`: the declarations and the registry rows derived
/// from them. `None` (crate-only build) writes EMPTY tables; the in-crate test
/// `addon_declarations_are_embedded` then fails, so such a build's tests
/// cannot pass vacuously.
fn gen_addon_decls(repo_root: Option<&Path>) {
    let mut decls: Vec<Decl> = Vec::new();
    if let Some(root) = repo_root {
        for f in STANDALONE_FILES.iter().filter(|f| f.starts_with("docker-compose.") && f.ends_with(".yml")) {
            let abs = root.join(f);
            let text = std::fs::read_to_string(&abs)
                .unwrap_or_else(|e| panic!("{}: unreadable ({e})", abs.display()));
            if let Some(d) = decl_of(f, &text) {
                decls.push(d);
            }
        }
        for (i, a) in decls.iter().enumerate() {
            for b in &decls[i + 1..] {
                assert!(a.key != b.key && a.consumer != b.consumer && a.addon != b.addon,
                    "{} and {} declare the same key, consumer or addon", a.overlay, b.overlay);
            }
        }
    } else {
        println!("cargo::warning=noo-cli built OUTSIDE the repo tree — add-on key declarations \
                  NOT embedded (the registry has no add-on rows)");
    }
    let strs = |v: &[String]| v.iter().map(|s| format!("{s:?}")).collect::<Vec<_>>().join(", ");
    println!("cargo::rerun-if-changed=src/addon_decl_parse.rs");
    let mut out = String::from(
        "// @generated by build.rs from each overlay's x-noo-addon.\n");
    out.push_str("pub static ADDON_DECLS: &[AddonDecl] = &[\n");
    for d in &decls {
        writeln!(out, "    AddonDecl {{ overlay: {:?}, addon: {:?}, consumer: {:?}, key: {:?}, \
                       containers: &[{}], scopes: &[{}], why: {:?} }},",
            d.overlay, d.addon, d.consumer, d.key, strs(&d.containers), strs(&d.scopes), d.why).unwrap();
    }
    out.push_str("];\n");
    out.push_str("pub static ADDON_KEY_SPECS: &[SecretSpec] = &[\n");
    for d in &decls {
        let holders = d.containers.join(", ");
        let why = d.why.as_deref().map(|w| format!(" Why: {w}")).unwrap_or_default();
        let consequence = format!(
            "{holders}'s OWN gateway key ({consumer}), delivered to that container only as \
             NOO_GATEWAY_KEY and exchanged at /api/addon/token for a 10-minute token carrying: \
             {scopes}. Declared in {overlay} (x-noo-addon), which is what this row is derived \
             from. It is the add-on's ONLY gateway credential: absent, every call it makes \
             is refused (the shared-secret fallback is retired, and the gateway refuses an \
             add-on's HMAC). `noo security service-key provision {name}` shows the request, mints, \
             stores, recreates and proves it: a key that is stored but never presented is \
             indistinguishable from no key at all.{why}",
            consumer = d.consumer,
            scopes = d.scopes.join(", "),
            overlay = d.overlay,
            name = d.addon.replace('_', "-"),
        );
        writeln!(out, "    SecretSpec {{ key: {:?}, class: Class::ProviderIssued, gen_bytes: 0, \
                       consequence: {:?}, consumers: &[{}], required_when: Requirement::Optional }},",
            d.key, consequence, strs(&d.containers)).unwrap();
    }
    out.push_str("];\n");
    let dest = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("addon_decls.rs");
    std::fs::write(&dest, out).expect("write addon_decls.rs");
}

/// The `pai enroll` node tooling. Same crate-only
/// tolerance as STANDALONE_ASSETS: a build outside the repo tree gets
/// EMPTY consts (enroll degrades to prep's fetch lane) instead of the
/// include_str! compile error that broke dev CI (the noo-cli job builds
/// the crate outside the tree).
fn write_enroll_assets(repo_root: Option<&std::path::Path>) {
    const ENROLL_ASSETS: &[(&str, &str)] = &[
        ("ASSET_PREP", "scripts/prep-host.sh"),
        ("ASSET_APPLY", "scripts/noo-apply.sh"),
        ("ASSET_FETCH", "scripts/noo-fetch.sh"),
        ("ASSET_DEENROLL", "scripts/deenroll-node-local.sh"),
        // The harness's unit and env template. Compiled in
        // for the same reason the applier is: `noo upgrade --nodes` stages
        // them from whatever tree the CONTROLLER is standing in, and that
        // tree is any revision at all. On 2026-09-19 a 0.5.42 binary — which
        // has the harness code — ran on a controller whose checkout predated
        // the template, and four of five nodes failed to stage with "No such
        // file or directory". A released binary must carry what it ships.
        ("ASSET_HARNESS_UNIT", "node-agent-go/deploy/noo-harness.service"),
        ("ASSET_HARNESS_ENV_TMPL", "node-agent-go/deploy/noo-harness.env.tmpl"),
    ];
    let mut out = String::from("// @generated by build.rs — pai enroll embedded node tooling.\n");
    for (name, rel) in ENROLL_ASSETS {
        match repo_root {
            Some(root) => {
                let abs = root.join(rel);
                println!("cargo::rerun-if-changed={}", abs.display());
                assert!(!abs.to_string_lossy().contains('"'),
                    "unexpected quote in asset path: {rel}");
                writeln!(out, "pub const {name}: &str = include_str!({:?});",
                    abs.to_string_lossy()).unwrap();
            }
            None => {
                writeln!(out, "pub const {name}: &str = \"\";").unwrap();
            }
        }
    }
    let dest = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("enroll_assets.rs");
    std::fs::write(&dest, out).expect("write enroll_assets.rs");
}

fn collect_dir(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => panic!("standalone asset dir {} unreadable: {e}", dir.display()),
    };
    let mut items: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    items.sort(); // deterministic order across builds
    for p in items {
        if p.is_dir() {
            collect_dir(root, &p, out);
        } else if p.is_file() {
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            out.push((rel, p));
        }
    }
}
