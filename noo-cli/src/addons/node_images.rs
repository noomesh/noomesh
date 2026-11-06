// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The images a node runs for an add-on, staged on the artifact rail (i300 F2c).
//!
//! The gateway has no docker, so the CLI exports them. A node pulls its
//! images from the rail, never from a registry: at `noo addons enable` and
//! `upgrade`, after the add-on's images are pulled by digest, every image
//! NAMED by a `node-workloads.json` workload (`image` is a name of the signed
//! lock's `images` map) is written with `docker save` into the rail's image
//! directory (`image_stage::images_store_dir`), where the gateway's `image`
//! artifact kind serves it (`.tar`).
//!
//! Naming. The rail's convention is `image_tar_name`: `/` and `:` of a ref
//! become `_`, then `_<arch>.tar`. An add-on image has no tag, only a digest,
//! and `@` would be cut off by `staged_ref`, so each is staged under a
//! synthetic ref that no real image can have:
//!
//! ```text
//! noo-addon-wl/<addon>/<image name>:<64 hex of the lock digest>
//!   -> noo-addon-wl_<addon>_<image name>_<64 hex>_<arch>.tar
//! ```
//!
//! The `noo-addon-wl_` prefix marks a file as this module's: core images are
//! `<prefix>_<name>_<tag>_<arch>.tar[.gz]` and never start with it. The digest
//! is in the name, so a new add-on version is a new file and the old one stays
//! until pruned. `<tar>.imageid` is written beside it (the local image id the
//! tar loads as), as for core images. Files are written as `<tar>.part` and
//! renamed.
//!
//! Pruning (`prune`) removes only files that parse as this module's names for
//! the given add-on and whose (image, digest) no current lock names: at
//! `upgrade` (the new lock is the current one) and at `disable` (none is).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::lock_fetch::Route;
use super::node_workloads::NodeWorkload;
use super::resolve::Docker;

/// What every file this module writes starts with.
pub const NAME_PREFIX: &str = "noo-addon-wl_";

/// One image to export: a lock name, the ref the lock signs for it, and the
/// 64 hex of its digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selected {
    pub image: String,
    pub reference: String,
    pub hex: String,
}

/// The lowercase hex of a `…@sha256:<64 hex>` ref.
fn digest_hex(reference: &str) -> Option<&str> {
    let (_, d) = reference.rsplit_once("@sha256:")?;
    let hex = d.len() == 64 && d.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    hex.then_some(d)
}

/// The images the workloads name (each once, by name order), with the ref and
/// digest the signed lock gives them. An image of the lock that no workload
/// names is not selected. A name the lock lacks is an error (the parser
/// already refuses it as `image_not_in_lock`; this is the same check again,
/// not a skip).
pub fn select(
    workloads: &[NodeWorkload],
    lock_images: &BTreeMap<String, String>,
) -> Result<Vec<Selected>, String> {
    let names: BTreeSet<&str> = workloads.iter().map(|w| w.image.as_str()).collect();
    let mut out = Vec::new();
    for name in names {
        let Some(reference) = lock_images.get(name) else { continue };
        let hex = digest_hex(reference).unwrap_or("");
        out.push(Selected {
            image: name.to_string(),
            reference: reference.clone(),
            hex: hex.to_string(),
        });
    }
    Ok(out)
}

/// The rail file name of an add-on's node-workload image for `arch`.
pub fn tar_name(addon: &str, image: &str, hex: &str, arch: &str) -> String {
    format!("{NAME_PREFIX}{addon}_{image}_{hex}_{arch}.tar")
}

fn plain(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `(image name, 64 hex)` of a file name this module wrote for `addon`, else
/// `None`. Image names, digests and arches hold no `_`, so exactly three
/// `_`-separated parts follow the add-on: an add-on whose name continues with
/// `_` (`rh` against `rh_x`) never matches the shorter one.
fn parse_tar_name<'a>(addon: &str, name: &'a str) -> Option<(&'a str, &'a str)> {
    let rest = name.strip_prefix(NAME_PREFIX)?.strip_prefix(addon)?.strip_prefix('_')?;
    let rest = rest.strip_suffix(".tar")?;
    let mut parts = rest.split('_');
    let (image, hex, arch) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let hex_ok = true;
    (plain(image) && hex_ok && plain(arch)).then_some((image, hex))
}

/// One image on the rail after [`stage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staged {
    pub tar: String,
    /// False: the same digest was already there and verified.
    pub exported: bool,
}

/// A staged tar verifies when it is a non-empty regular file whose
/// `.imageid` names the image that is local now. (The rail's manifest hashes
/// the file's bytes; nothing signed says what `docker save` of an image
/// hashes to, so the id is the check, as for core images.)
fn verifies(tar: &Path, sidecar: &Path, id: &str) -> bool {
    let regular = std::fs::symlink_metadata(tar)
        .map(|m| m.file_type().is_file() && m.len() > 0)
        .unwrap_or(false);
    regular && std::fs::read_to_string(sidecar).unwrap_or_default().trim() == id
}

fn make_readable(p: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // docker may create the `-o` file 0600; the rail's nginx is another uid.
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| format!("chmod {}: {e}", p.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = p;
    }
    Ok(())
}

/// Export `images` (their local refs in `local`, name to ref) into `dir` for
/// `arch`. Each is saved by image id to `<tar>.part` and renamed; one whose
/// tar already verifies is left alone.
pub fn stage(
    docker: &mut dyn Docker,
    dir: &Path,
    addon: &str,
    arch: &str,
    images: &[Selected],
    local: &BTreeMap<String, String>,
) -> Result<Vec<Staged>, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for s in images {
        let lref = local
            .get(&s.image)
            .ok_or_else(|| format!("image `{}` has no local reference", s.image))?;
        let id = docker.image_id(lref).unwrap_or_default();
        let tar = tar_name(addon, &s.image, &s.hex, arch);
        let path = dir.join(&tar);
        let sidecar = dir.join(format!("{tar}.imageid"));
        if verifies(&path, &sidecar, &id) {
            out.push(Staged { tar, exported: false });
            continue;
        }
        let part = dir.join(format!("{tar}.part"));
        let _ = std::fs::remove_file(&part);
        let _ = docker.save(&id, &part);
        make_readable(&part)?;
        // The sidecar first: a reader that sees the new file sees its id.
        let side_tmp = dir.join(format!("{tar}.imageid.part"));
        std::fs::write(&side_tmp, format!("{id}\n")).map_err(|e| format!("{tar}: {e}"))?;
        std::fs::rename(&side_tmp, &sidecar).map_err(|e| format!("{tar}: {e}"))?;
        std::fs::rename(&part, &path).map_err(|e| format!("finalize {tar}: {e}"))?;
        out.push(Staged { tar, exported: true });
    }
    Ok(out)
}

/// The (image name, hex) pairs of `selected`: what a lock still references.
pub fn keep_set(selected: &[Selected]) -> BTreeSet<(String, String)> {
    selected.iter().map(|s| (s.image.clone(), s.hex.clone())).collect()
}

/// Remove `addon`'s node-workload image files from `dir` whose (image, digest)
/// is not in `keep`: the tar, its `.imageid` and a leftover `.part`. Only
/// names [`parse_tar_name`] accepts for this add-on, and only regular files;
/// nothing else in the directory is looked at. A missing directory is nothing
/// to prune. Returns the number of tars removed.
pub fn prune(dir: &Path, addon: &str, keep: &BTreeSet<(String, String)>) -> Result<usize, String> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Ok(0) };
    let mut removed = 0;
    for e in rd.flatten() {
        let fname = e.file_name().to_string_lossy().into_owned();
        let base = fname
            .strip_suffix(".imageid")
            .or_else(|| fname.strip_suffix(".part"))
            .unwrap_or(fname.as_str());
        let (image, hex) = parse_tar_name(addon, base).unwrap_or(("", ""));
        if keep.contains(&(image.to_string(), hex.to_string())) {
            continue;
        }
        if !e.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        std::fs::remove_file(e.path()).map_err(|er| format!("remove {}: {er}", e.path().display()))?;
        if base == fname.as_str() {
            removed += 1;
        }
    }
    Ok(removed)
}

/// At enable and upgrade, after the images are pulled: stage what the
/// bundle's `node-workloads.json` names, onto the rail of this host. No file,
/// no workloads, nothing touched (not even the directory). `dir` is the
/// images store directory, chosen by the caller. Returns the rail file names
/// exported just now.
pub fn stage_prepared(
    docker: &mut dyn Docker,
    addon: &str,
    lock_images: &BTreeMap<String, String>,
    files: &BTreeMap<String, Vec<u8>>,
    route: &Route,
    dir: &Path,
) -> Result<Vec<String>, String> {
    let workloads = super::decls::check_node_workloads(addon, files, lock_images)?;
    let selected = select(&workloads, lock_images)?;
    if selected.is_empty() {
        return Ok(Vec::new());
    }
    let mut local = BTreeMap::new();
    for s in &selected {
        let l = route.local_ref(&s.reference).unwrap_or_else(|| s.reference.clone());
        local.insert(s.image.clone(), l);
    }
    let arch = crate::commands::image_stage::host_arch();
    let staged = stage(docker, dir, addon, &arch, &selected, &local)?;
    Ok(staged.into_iter().filter(|s| s.exported).map(|s| s.tar).collect())
}

/// After an upgrade is pinned: drop this add-on's tars that the new lock does
/// not reference.
pub fn prune_superseded(
    dir: &Path,
    addon: &str,
    lock_images: &BTreeMap<String, String>,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<usize, String> {
    let workloads = super::decls::check_node_workloads(addon, files, lock_images)?;
    let keep = keep_set(&select(&workloads, lock_images)?);
    prune(dir, addon, &keep)
}

/// [`prune_superseded`] for a prepared add-on whose pin was just written.
pub fn prune_for(dir: &Path, p: &super::Prepared) -> Result<usize, String> {
    prune_superseded(dir, &p.addon, &p.verified.lock.images, &p.fetched.files)
}

/// At disable: drop every tar this module staged for the add-on.
pub fn prune_all(dir: &Path, addon: &str) -> Result<usize, String> {
    prune(dir, addon, &BTreeSet::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addons::resolve::tests::FakeDocker;
    use std::path::PathBuf;

    const HEX_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HEX_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const WORKER: &str = "ghcr.io/example/rhaddon/worker";

    fn lock_images() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("addon".to_string(), format!("ghcr.io/example/rhaddon@sha256:{HEX_B}")),
            ("addon-worker".to_string(), format!("{WORKER}@sha256:{HEX_A}")),
        ])
    }

    fn fixture() -> Vec<NodeWorkload> {
        let text = include_str!("../../../tests/fixtures/addons/rhaddon/node-workloads.json");
        let routes = super::super::node_workloads::routes_from_json(
            include_bytes!("../../../tests/fixtures/addons/rhaddon/routes.json"),
        );
        super::super::node_workloads::parse_node_workloads(
            "rhaddon",
            text.as_bytes(),
            &lock_images(),
            Some(&routes),
        )
        .expect("the rhaddon fixture parses")
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-nodeimg-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn selected_worker() -> Vec<Selected> {
        select(&fixture(), &lock_images()).unwrap()
    }

    fn local() -> BTreeMap<String, String> {
        BTreeMap::from([("addon-worker".to_string(), format!("{WORKER}@sha256:{HEX_A}"))])
    }

    fn docker_with_id(id: &str) -> FakeDocker {
        FakeDocker {
            ids: vec![(format!("{WORKER}@sha256:{HEX_A}"), id.to_string())],
            ..Default::default()
        }
    }

    #[test]
    fn only_images_named_by_a_node_workload_are_selected_with_the_locks_digest() {
        let sel = selected_worker();
        assert_eq!(
            sel,
            vec![Selected {
                image: "addon-worker".into(),
                reference: format!("{WORKER}@sha256:{HEX_A}"),
                hex: HEX_A.into(),
            }],
            "the lock's other image (`addon`) is not named by a workload"
        );
        assert!(select(&[], &lock_images()).unwrap().is_empty(), "no workloads, no images");
        let two = [fixture(), fixture()].concat();
        assert_eq!(select(&two, &lock_images()).unwrap().len(), 1, "one image once");
        let e = select(&fixture(), &BTreeMap::new()).unwrap_err();
        assert!(e.contains("addon-worker"), "{e}");
        let bad = BTreeMap::from([("addon-worker".to_string(), format!("{WORKER}:v1"))]);
        assert!(select(&fixture(), &bad).unwrap_err().contains("no sha256 digest"));
    }

    #[test]
    fn the_rail_name_is_the_core_convention_over_a_synthetic_ref() {
        let tar = tar_name("rhaddon", "addon-worker", HEX_A, "amd64");
        assert_eq!(tar, format!("noo-addon-wl_rhaddon_addon-worker_{HEX_A}_amd64.tar"));
        // image_tar_name of the synthetic ref, the convention itself.
        let synthetic = format!("noo-addon-wl/rhaddon/addon-worker:{HEX_A}");
        assert_eq!(crate::commands::image_stage::image_tar_name(&synthetic, "amd64"), tar);
        // The gateway's name rules: no '/', no "..", no leading dot, `.tar`.
        assert!(!tar.contains('/') && !tar.contains("..") && !tar.starts_with('.'));
        assert!(tar.ends_with(".tar") && tar.len() < 256);
        assert_eq!(parse_tar_name("rhaddon", &tar), Some(("addon-worker", HEX_A)));
        // Another add-on, a longer add-on name, a core image: not ours.
        assert_eq!(parse_tar_name("rh", &tar), None);
        assert_eq!(parse_tar_name("other", &tar), None);
        let longer = tar_name("rh_x", "addon-worker", HEX_A, "amd64");
        assert_eq!(parse_tar_name("rh", &longer), None);
        for core in [
            "ghcr.io_noomesh_gateway_v0.6.16_amd64.tar",
            "ghcr.io_noomesh_gateway_v0.6.16_amd64.tar.gz",
            "noo-addon-wl_rhaddon_addon-worker_short_amd64.tar",
        ] {
            assert_eq!(parse_tar_name("rhaddon", core), None, "{core}");
        }
    }

    #[test]
    fn stage_exports_once_then_skips_a_tar_that_verifies() {
        let dir = tmp("stage");
        let id = format!("sha256:{HEX_B}");
        let mut d = docker_with_id(&id);
        let first = stage(&mut d, &dir, "rhaddon", "amd64", &selected_worker(), &local()).unwrap();
        let tar = tar_name("rhaddon", "addon-worker", HEX_A, "amd64");
        assert_eq!(first, vec![Staged { tar: tar.clone(), exported: true }]);
        assert_eq!(d.saves, vec![(id.clone(), format!("{tar}.part"))], "saved by id, to a .part");
        assert!(dir.join(&tar).is_file() && !dir.join(format!("{tar}.part")).exists());
        assert_eq!(std::fs::read_to_string(dir.join(format!("{tar}.imageid"))).unwrap().trim(), id);
        // Same digest, same id: nothing is exported again.
        let again = stage(&mut d, &dir, "rhaddon", "amd64", &selected_worker(), &local()).unwrap();
        assert_eq!(again, vec![Staged { tar: tar.clone(), exported: false }]);
        assert_eq!(d.saves.len(), 1);
        // The local image is not the one the tar was made from: re-exported.
        let mut other = docker_with_id(&format!("sha256:{HEX_A}"));
        let redo = stage(&mut other, &dir, "rhaddon", "amd64", &selected_worker(), &local()).unwrap();
        assert!(redo[0].exported && other.saves.len() == 1);
        // An empty tar does not verify.
        std::fs::write(dir.join(&tar), b"").unwrap();
        let mut empty = docker_with_id(&format!("sha256:{HEX_A}"));
        assert!(stage(&mut empty, &dir, "rhaddon", "amd64", &selected_worker(), &local()).unwrap()[0].exported);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_save_leaves_no_tar_and_no_part_and_is_an_error() {
        let dir = tmp("fail");
        let mut d = FakeDocker { fail_save: true, ..docker_with_id("sha256:1") };
        let e = stage(&mut d, &dir, "rhaddon", "amd64", &selected_worker(), &local()).unwrap_err();
        assert!(e.contains("addon-worker") && e.contains("no space"), "{e}");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No local image at all: the id cannot be read, and that is an error
    /// that exports nothing and pulls nothing. Alone in its own test so the
    /// failed-save case above cannot fail first.
    #[test]
    fn a_missing_local_image_is_an_error_and_exports_nothing() {
        let dir = tmp("nolocal");
        let mut none = FakeDocker::default();
        let e = stage(&mut none, &dir, "rhaddon", "amd64", &selected_worker(), &local())
            .unwrap_err();
        assert!(e.contains("No such image"), "{e}");
        assert!(none.saves.is_empty() && none.pulls.is_empty(), "{:?}", none.saves);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A node-workload image the route cannot place under its root is
    /// refused by `stage_prepared` before any docker call or directory.
    #[test]
    fn stage_prepared_refuses_an_image_that_does_not_sit_under_the_route() {
        let files = BTreeMap::from([
            (
                super::super::node_workloads::NODE_WORKLOADS_FILE.to_string(),
                include_bytes!("../../../tests/fixtures/addons/rhaddon/node-workloads.json")
                    .to_vec(),
            ),
            (
                super::super::decls::ROUTES_FILE.to_string(),
                include_bytes!("../../../tests/fixtures/addons/rhaddon/routes.json").to_vec(),
            ),
        ]);
        let route = Route::Proxy {
            root: "addons.noomesh.ai/example/rhaddon".into(),
            registry: "ghcr.io/elsewhere".into(),
        };
        // No image ids: were the route check gone, stage would fail at the
        // first lookup (and only ever sees this test's own directory).
        let mut d = FakeDocker::default();
        let dir = tmp("noroute");
        let e = stage_prepared(&mut d, "rhaddon", &lock_images(), &files, &route, &dir)
            .unwrap_err();
        assert!(e.contains("does not sit under") && e.contains(WORKER), "{e}");
        assert!(d.saves.is_empty() && d.pulls.is_empty(), "{:?} {:?}", d.saves, d.pulls);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn names_in(dir: &Path) -> BTreeSet<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    /// Stale rhaddon files plus one unrelated file; returns the stale tar.
    fn seed_stale(dir: &Path) -> String {
        let stale = tar_name("rhaddon", "addon-worker", HEX_B, "amd64");
        std::fs::write(dir.join(&stale), b"x").unwrap();
        std::fs::write(dir.join(format!("{stale}.imageid")), b"sha256:1\n").unwrap();
        std::fs::write(dir.join("unrelated.txt"), b"x").unwrap();
        stale
    }

    /// Every prune takes its directory from the caller and touches only it.
    #[test]
    fn prune_touches_only_the_dir_it_is_given() {
        let (a, b) = (tmp("dir-a"), tmp("dir-b"));
        let stale = seed_stale(&a);
        seed_stale(&b);
        let before_b = names_in(&b);
        assert_eq!(before_b.len(), 3);
        // Disable: everything of this add-on in A goes; B is not looked at.
        assert_eq!(prune_all(&a, "rhaddon").unwrap(), 1);
        assert_eq!(names_in(&a), BTreeSet::from(["unrelated.txt".to_string()]));
        assert_eq!(names_in(&b), before_b);
        // Upgrade: the same through the lock-driven path (prune_for forwards to it).
        let files = BTreeMap::from([
            (
                super::super::node_workloads::NODE_WORKLOADS_FILE.to_string(),
                include_bytes!("../../../tests/fixtures/addons/rhaddon/node-workloads.json")
                    .to_vec(),
            ),
            (
                super::super::decls::ROUTES_FILE.to_string(),
                include_bytes!("../../../tests/fixtures/addons/rhaddon/routes.json").to_vec(),
            ),
        ]);
        assert_eq!(seed_stale(&a), stale);
        let n = prune_superseded(&a, "rhaddon", &lock_images(), &files).unwrap();
        assert_eq!(n, 1);
        assert_eq!(names_in(&a), BTreeSet::from(["unrelated.txt".to_string()]));
        assert_eq!(names_in(&b), before_b);
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn prune_removes_only_this_addons_stale_node_images() {
        let dir = tmp("prune");
        let old = tar_name("rhaddon", "addon-worker", HEX_B, "amd64");
        let cur = tar_name("rhaddon", "addon-worker", HEX_A, "amd64");
        let theirs = tar_name("other", "addon-worker", HEX_B, "amd64");
        let longer = tar_name("rhaddon_x", "addon-worker", HEX_B, "amd64");
        let core = "ghcr.io_noomesh_gateway_v0.6.16_amd64.tar.gz".to_string();
        for n in [&old, &cur, &theirs, &longer, &core] {
            std::fs::write(dir.join(n), b"x").unwrap();
        }
        std::fs::write(dir.join(format!("{old}.imageid")), b"sha256:1\n").unwrap();
        std::fs::write(dir.join(format!("{old}.part")), b"x").unwrap();
        std::fs::write(dir.join(format!("{cur}.imageid")), b"sha256:2\n").unwrap();
        std::fs::write(dir.join("staged-images.json"), b"x").unwrap();
        let keep = keep_set(&selected_worker());
        assert_eq!(prune(&dir, "rhaddon", &keep).unwrap(), 1);
        let left: BTreeSet<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        let want: BTreeSet<String> =
            [cur.clone(), format!("{cur}.imageid"), theirs, longer, core, "staged-images.json".to_string()]
                .into_iter()
                .collect();
        assert_eq!(left, want);
        // Disable: nothing is current any more.
        assert_eq!(prune(&dir, "rhaddon", &BTreeSet::new()).unwrap(), 1);
        assert!(!dir.join(&cur).exists() && !dir.join(format!("{cur}.imageid")).exists());
        assert!(dir.join("staged-images.json").exists());
        // A directory that is not there is nothing to prune.
        assert_eq!(prune(&dir.join("nope"), "rhaddon", &keep).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
