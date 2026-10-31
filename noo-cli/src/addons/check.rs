// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo addons check <bundle-dir>` — the contract test of an add-on author.
//!
//! The checks `noo addons enable` runs on a verified bundle's files, run on a
//! directory instead: [`decls::check_bundle`] (`system.json`, `workloads.json`,
//! `resources.json`; `resolve::check`) and then [`guards::check_bundle_files`]
//! (the overlay's secrets, a third-party name, the runtime rules;
//! `guards::guard_install`). Both are called, not copied, and their errors
//! are wrapped in the same [`Refusal`], so a bundle this accepts is one those
//! two steps of enable accept, and the refusal text is enable's.
//!
//! `routes.json` is then checked by the gateway's own rules: the
//! `addon-manifest` crate is compiled into both the gateway and this binary,
//! so [`check_routes`] refuses what the gateway would refuse at load, with
//! the gateway's sentence (noomesh-internal i302). One rule needs the
//! gateway's front door (is a write route where a User may write?); every
//! route it applies to is listed as not checked, never passed.
//!
//! Not covered, because they need what a directory does not have: the
//! signature and file hashes of the lock, the trust key, the stack's base-image
//! row, and the pull. The core's
//! compose facts are the files embedded in this binary ([`Core::embedded`]),
//! not a live install's, so an install with local compose edits can still
//! refuse what this passes.
//!
//! Nothing here installs, writes, or opens a socket: the input is the
//! directory and the embedded core.

use std::collections::BTreeMap;
use std::path::Path;

use addon_manifest::{FrontDoor, ROUTES_FILE};

use super::guards::{self, Checked, Core};
use super::resolve::Refusal;
use super::{decls, trust};

/// What a bundle directory that passed was checked for.
#[derive(Debug)]
pub struct DirChecked {
    /// Enable's guard and resources checks ([`check_files`]).
    pub guards: Checked,
    /// `None`: the bundle ships no routes.json (the gateway mounts nothing
    /// for it). `Some(rules)`: it passed the gateway's rules, except `rules`,
    /// one sentence per route the front-door rule could not be applied to.
    pub routes: Option<Vec<String>>,
}

/// What can still refuse a bundle this passes. Printed on every pass (and in
/// `--json` as `not_checked`), with the routes the front-door rule could not
/// be applied to ([`DirChecked::routes`]), so exit 0 means "passes enable's
/// guard and resources checks and the gateway's routes.json rules" and
/// nothing more.
pub const NOT_CHECKED: &[&str] = &[
    "the lock's signature and file hashes",
    "the trust key",
    "the stack's base-image row",
    "the image pull",
];

/// The bundle's checked files (name to bytes) from `dir`. A symlink or a
/// directory under a checked name is not read (as `pins::materialised_files`).
/// A directory with none of them is an error: there would be nothing to check.
pub fn read_bundle_dir(dir: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let meta = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    let mut files = BTreeMap::new();
    for name in decls::CHECKED_FILES {
        let p = dir.join(name);
        if !std::fs::symlink_metadata(&p).map(|m| m.file_type().is_file()).unwrap_or(false) {
            continue;
        }
        let bytes = std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        files.insert(name.to_string(), bytes);
    }
    if files.is_empty() {
        return Err(format!("{} holds none of {}, so there is nothing to check", dir.display(), decls::CHECKED_FILES.join(", ")));
    }
    Ok(files)
}

/// The add-on's name when none is given: the directory's name (a
/// materialised bundle lives at `addons/<name>/`).
pub fn name_of_dir(dir: &Path) -> Result<String, String> {
    let abs = std::fs::canonicalize(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let name = abs.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
    if trust::name_ok(&name) {
        Ok(name)
    } else {
        Err(format!("`{name}` is not an add-on name (lowercase letters, digits, `-`, `_`); give it with --name"))
    }
}

/// What enable does with a bundle's files, as one pure step: the declarations
/// first (`resolve::check`), then the guards (`guards::guard_install`), the
/// guards as `resolve::third_party` decides for `addon`. Either failure is
/// `Refusal::Decl`, as it is in enable.
pub fn check_files(addon: &str, files: &BTreeMap<String, Vec<u8>>, core: &Core) -> Result<Checked, Refusal> {
    decls::check_bundle(addon, files).map_err(Refusal::Decl)?;
    guards::check_bundle_files(addon, files, super::resolve::third_party(addon), core).map_err(Refusal::Decl)
}

/// The bundle's routes.json under the gateway's own rules
/// (`addon_manifest::validate`, the function the gateway calls at load).
/// `Ok(None)`: the bundle ships none. `Ok(Some(rules))`: valid, except
/// `rules`, which only the gateway can decide (see [`DirChecked::routes`]).
/// `Err` carries the gateway's sentence.
pub fn check_routes(addon: &str, files: &BTreeMap<String, Vec<u8>>) -> Result<Option<Vec<String>>, Refusal> {
    let Some(raw) = files.get(ROUTES_FILE) else { return Ok(None) };
    let refused = |why: String| Refusal::Decl(format!("{ROUTES_FILE} is refused as the gateway refuses it at load: {why}"));
    let text = std::str::from_utf8(raw).map_err(|e| refused(format!("not UTF-8: {e}")))?;
    let manifest = addon_manifest::parse(text).map_err(refused)?;
    let checked = addon_manifest::validate(&manifest, addon, FrontDoor::NotHere).map_err(refused)?;
    Ok(Some(checked.unchecked))
}

/// [`check_routes`] as the pin path runs it (`noo addons enable | upgrade`,
/// `upgrade --check`): a bundle the gateway would refuse whole at load is
/// refused here, with the gateway's sentence, before an image is pulled or a
/// pin, overlay or switch is written. What only the gateway's front door can
/// decide is not judged here (`noo addons check` lists it).
pub fn refuse_bad_routes(addon: &str, files: &BTreeMap<String, Vec<u8>>) -> Result<(), Refusal> {
    check_routes(addon, files).map(|_| ()).map_err(|r| match r {
        Refusal::Decl(e) => Refusal::Decl(format!("{e} (nothing was changed)")),
        other => other,
    })
}

/// [`check_files`] and then [`check_routes`] over a bundle directory against
/// the embedded core. `Err` is the text enable would print for the refusal
/// (`Refusal::why`); a directory or core that cannot be read is an error in
/// the same string form.
pub fn check_dir_with(dir: &Path, addon: &str, core: &Core) -> Result<DirChecked, String> {
    let files = read_bundle_dir(dir)?;
    let guards = check_files(addon, &files, core).map_err(|r| r.why(addon))?;
    let routes = check_routes(addon, &files).map_err(|r| r.why(addon))?;
    Ok(DirChecked { guards, routes })
}

/// [`check_dir_with`] against the core embedded in this binary.
pub fn check_dir(dir: &Path, addon: &str) -> Result<DirChecked, String> {
    let core = Core::embedded().map_err(|e| format!("add-on {addon} could not be checked: {e}"))?;
    check_dir_with(dir, addon, &core)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core() -> Core {
        Core::from_texts(&["services:\n  gateway:\n    image: g\nvolumes:\n  pgdata:\n  noo-models:\n".to_string()]).unwrap().with_tables()
    }

    /// A bundle directory under a temp dir, named `name`, holding the fixture
    /// bundle's files.
    fn fixture_dir(tag: &str, name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("noo-addons-check-{tag}-{}", std::process::id())).join(name);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("docker-compose.yml"), include_bytes!("../../../tests/fixtures/addons/rhaddon/docker-compose.yml")).unwrap();
        std::fs::write(d.join("resources.json"), include_bytes!("../../../tests/fixtures/addons/rhaddon/resources.json")).unwrap();
        std::fs::write(d.join("system.json"), include_bytes!("../../../tests/fixtures/addons/rhaddon/system.json")).unwrap();
        std::fs::write(d.join("routes.json"), include_bytes!("../../../tests/fixtures/addons/rhaddon/routes.json")).unwrap();
        d
    }

    fn clean(d: &Path) {
        let _ = std::fs::remove_dir_all(d.parent().unwrap());
    }

    /// A pass must not imply more than was checked: every refusal source
    /// this verb cannot see is named.
    #[test]
    fn a_pass_names_what_it_did_not_check() {
        let all = NOT_CHECKED.join(" ");
        for must in ["signature", "trust key", "base-image", "pull"] {
            assert!(all.contains(must), "{must} missing from {all}");
        }
        // routes.json is checked now (i302); listing it would understate the pass.
        assert!(!all.contains("routes.json"), "{all}");
        let usage = crate::usage::USAGE.iter().find(|(w, _, _)| *w == ["addons", "check"]).expect("usage row");
        assert!(usage.2.contains("routes.json") && !usage.2.contains("not routes.json") && usage.2.contains("signature"), "{}", usage.2);
    }

    #[test]
    fn a_good_bundle_directory_passes_and_every_part_was_read() {
        let d = fixture_dir("good", "rhaddon");
        let c = check_dir_with(&d, "rhaddon", &core()).unwrap();
        assert_eq!(c.guards.mounts, 2, "the overlay and resources.json were both read");
        assert_eq!(c.routes, Some(vec![]), "routes.json was read and nothing in it needs the front door");
        assert_eq!(name_of_dir(&d).unwrap(), "rhaddon");
        clean(&d);
    }

    /// Reverting `check_files` to skip either step fails one of these: the
    /// text is the one `Refusal::Decl` gives enable, from the same functions.
    #[test]
    fn a_refused_bundle_gets_the_text_enable_prints() {
        let d = fixture_dir("bad", "rhaddon");
        let good = std::fs::read_to_string(d.join("docker-compose.yml")).unwrap();
        let files = read_bundle_dir(&d).unwrap();

        // system.json with schema "public": decls::check_bundle refuses it.
        std::fs::write(d.join("system.json"), r#"{"schema":"public","role":"noo_app","ddl_role":"noo"}"#).unwrap();
        let e = check_dir_with(&d, "rhaddon", &core()).unwrap_err();
        let want = decls::check_bundle("rhaddon", &read_bundle_dir(&d).unwrap()).unwrap_err();
        assert_eq!(e, Refusal::Decl(want).why("rhaddon"));
        assert!(e.starts_with("rhaddon's signed bundle is refused: ") && e.contains("`schema`") && e.ends_with("the vendor must fix and re-sign it"), "{e}");
        std::fs::write(d.join("system.json"), &files["system.json"]).unwrap();

        // A resources.json that is not one.
        std::fs::write(d.join("resources.json"), "{").unwrap();
        let e = check_dir_with(&d, "rhaddon", &core()).unwrap_err();
        assert!(e.starts_with("rhaddon's signed bundle is refused: "), "{e}");
        assert_eq!(e, Refusal::Decl(decls::check_bundle("rhaddon", &read_bundle_dir(&d).unwrap()).unwrap_err()).why("rhaddon"));
        std::fs::write(d.join("resources.json"), &files["resources.json"]).unwrap();

        // An overlay that sources a core-owned secret: the guards refuse it.
        std::fs::write(d.join("docker-compose.yml"), format!("{good}secrets:\n  stolen:\n    x-noo-source: NOO_JWT_SECRET\n")).unwrap();
        let e = check_dir_with(&d, "rhaddon", &core()).unwrap_err();
        let bad_files = read_bundle_dir(&d).unwrap();
        let want = guards::check_bundle_files("rhaddon", &bad_files, true, &core()).unwrap_err();
        assert_eq!(e, Refusal::Decl(want).why("rhaddon"));
        assert!(e.contains("NOO_JWT_SECRET"), "{e}");
        clean(&d);
    }

    /// routes.json is refused with the gateway's own sentence: the text is
    /// `addon_manifest::validate`'s, the function the gateway runs at load.
    /// Reverting `check_dir_with` to skip `check_routes` fails every case.
    #[test]
    fn a_bad_routes_json_gets_the_gateways_refusal() {
        let d = fixture_dir("routes", "rhaddon");
        let good: serde_json::Value = serde_json::from_slice(&std::fs::read(d.join("routes.json")).unwrap()).unwrap();
        // What the case is, how it spoils the manifest, the refusal it earns.
        type Case = (&'static str, fn(&mut serde_json::Value), &'static str);
        let cases: [Case; 4] = [
            ("unknown role", |m: &mut serde_json::Value| m["routes"][0]["min_role"] = "owner".into(), "min_role \"owner\" is not a role"),
            ("wrong addon", |m: &mut serde_json::Value| m["addon"] = "other".into(), "it names add-on \"other\", but was delivered for \"rhaddon\""),
            ("duplicate route", |m: &mut serde_json::Value| {
                let first = m["routes"][0].clone();
                m["routes"].as_array_mut().unwrap().push(first);
            }, "route name \"status\" appears twice"),
            ("no routes", |m: &mut serde_json::Value| m["routes"] = serde_json::json!([]), "it declares no routes"),
        ];
        for (what, edit, want) in cases {
            let mut m = good.clone();
            edit(&mut m);
            let text = m.to_string();
            std::fs::write(d.join("routes.json"), &text).unwrap();
            let e = check_dir_with(&d, "rhaddon", &core()).unwrap_err();
            let gateway = addon_manifest::validate(&addon_manifest::parse(&text).unwrap(), "rhaddon", FrontDoor::NotHere).unwrap_err();
            assert!(gateway.contains(want), "{what}: {gateway}");
            assert_eq!(e, Refusal::Decl(format!("{ROUTES_FILE} is refused as the gateway refuses it at load: {gateway}")).why("rhaddon"), "{what}");
        }
        // Not a manifest at all (an unknown key): serde's refusal, as the gateway logs it.
        std::fs::write(d.join("routes.json"), r#"{"version":1,"addon":"rhaddon","routez":[]}"#).unwrap();
        let e = check_dir_with(&d, "rhaddon", &core()).unwrap_err();
        assert!(e.contains("not a valid manifest"), "{e}");
        clean(&d);
    }

    /// The one rule that needs the gateway's front door is reported, per
    /// route, as not checked: a public write never passes silently.
    #[test]
    fn a_public_write_is_listed_as_not_checked_never_passed() {
        let d = fixture_dir("routes-write", "rhaddon");
        let mut m: serde_json::Value = serde_json::from_slice(&std::fs::read(d.join("routes.json")).unwrap()).unwrap();
        m["routes"].as_array_mut().unwrap().push(serde_json::json!({"name": "reset", "method": "POST", "path": "/api/rhaddon/reset"}));
        std::fs::write(d.join("routes.json"), m.to_string()).unwrap();
        let c = check_dir_with(&d, "rhaddon", &core()).unwrap();
        let rules = c.routes.expect("routes.json was read");
        assert_eq!(rules.len(), 1, "{rules:?}");
        assert!(rules[0].contains("\"reset\"") && rules[0].contains("POST \"/api/rhaddon/reset\"") && rules[0].contains("front door"), "{}", rules[0]);
        // With a front door to ask, the same rule decides instead of listing.
        let parsed = addon_manifest::parse(&m.to_string()).unwrap();
        let admits = |_: &str, _: &str| true;
        let e = addon_manifest::validate(&parsed, "rhaddon", FrontDoor::Asks(&admits)).unwrap_err();
        assert!(e.contains("would be callable by a User-tier caller"), "{e}");
        let refuses = |_: &str, _: &str| false;
        assert_eq!(addon_manifest::validate(&parsed, "rhaddon", FrontDoor::Asks(&refuses)).unwrap().unchecked, Vec::<String>::new());
        clean(&d);
    }

    /// A third-party name that is core's is refused (guards::name_collision).
    #[test]
    fn a_name_that_is_cores_is_refused_for_a_third_party() {
        let d = fixture_dir("name", "gateway");
        for f in ["resources.json", "system.json", "routes.json"] {
            std::fs::remove_file(d.join(f)).unwrap();
        }
        std::fs::write(d.join("docker-compose.yml"), "services: {}\n").unwrap();
        let e = check_dir_with(&d, "gateway", &core()).unwrap_err();
        assert!(e.contains("cannot share a name with core"), "{e}");
        clean(&d);
    }

    #[test]
    fn a_missing_or_empty_directory_is_an_error_not_a_pass() {
        let d = fixture_dir("empty", "rhaddon");
        let nothing = d.join("nothing-here");
        assert!(check_dir_with(&nothing, "rhaddon", &core()).is_err());
        std::fs::create_dir_all(&nothing).unwrap();
        assert!(check_dir_with(&nothing, "rhaddon", &core()).unwrap_err().contains("nothing to check"));
        assert!(name_of_dir(&d.join("docker-compose.yml")).is_err(), "a file is not a bundle");
        clean(&d);
    }

    /// The function takes a directory, a name and a `Core`, so it reaches no
    /// network and no install; the only read is the directory itself.
    #[test]
    fn the_check_reads_only_the_directory() {
        let src = include_str!("check.rs").split("#[cfg(test)]").next().unwrap();
        for banned in ["lock_fetch", "std::net", "ureq", "repo_root", "of_install", "guard_install", "std::process"] {
            assert!(!src.contains(&format!("{banned}::")) && !src.contains(&format!("use {banned}")), "check.rs must not use {banned}");
        }
        let d = fixture_dir("pure", "rhaddon");
        let before = std::fs::read_dir(&d).unwrap().count();
        check_dir_with(&d, "rhaddon", &core()).unwrap();
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), before, "nothing was written");
        clean(&d);
    }

    /// The embedded core is a real core when this build has the deploy slice
    /// (a crate-only build embeds none and refuses, said plainly).
    #[test]
    fn the_embedded_core_is_the_shipped_compose_files() {
        match Core::embedded() {
            Ok(c) => assert!(c.services.contains("gateway"), "{c:?}"),
            Err(e) => {
                assert!(e.contains("no core compose file"), "{e}");
            }
        }
    }
}
