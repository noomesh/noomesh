// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// The placement route (H3b-2) reads it; the desired-config builder (H3b-3)
// will read rail_image and staged_set too.
#![allow(dead_code)]

//! Where the gateway reads what an add-on's node workloads are and which
//! image each one runs (i300 H3b-1).
//!
//! * **The declaration.** The launcher copies an add-on's SIGNED
//!   `node-workloads.json` beside its `workloads.json`, to
//!   `WORKLOADS_DIR/<addon>/node-workloads.json` (`scripts/lib-dist.sh`
//!   `addon_decls_materialise`, from the `decl` lines `noo addons launch-pins`
//!   prints only for files the verified lock lists). [`read_decl`] validates it
//!   with the one gateway validator ([`crate::node_workloads::validate_decl`])
//!   and only for a REGISTERED add-on ([`declared`]).
//! * **The image.** The gateway never reads an add-on lock. The rail is the
//!   controller's staged truth (A6): the CLI exports each image a workload
//!   names as `noo-addon-wl_<addon>_<image>_<64 hex of the lock digest>_<arch>.tar`
//!   with the image ID it loads as in `<tar>.imageid`, and prunes every
//!   (image, digest) the current lock does not name at `upgrade` and `disable`
//!   (`noo-cli/src/addons/node_images.rs`). So exactly one tar per (add-on,
//!   image, arch) gives the entry's `{name, digest, id, artifact}`
//!   ([`rail_image`]); none, several, or a missing or malformed sidecar is
//!   `image_missing`, never a guess.

use std::path::Path;

use crate::node_workloads::{code, routes_from_json, validate_decl, NodeWorkloads, Refusal};

pub const NODE_WORKLOADS_FILE: &str = "node-workloads.json";
pub const ROUTES_FILE: &str = "routes.json";
/// What every rail file the CLI exports for an add-on workload starts with.
pub const ARTIFACT_PREFIX: &str = "noo-addon-wl_";
/// Largest node-workloads.json read (the CLI's cap).
pub const MAX_DECL_BYTES: u64 = 64 * 1024;
/// Largest `.imageid` sidecar read.
const MAX_SIDECAR_BYTES: u64 = 256;

/// One image an add-on workload runs, as the rail holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RailImage {
    pub image: String,
    /// `sha256:<64 hex>`: the lock (registry manifest) digest, from the name.
    pub digest: String,
    /// `sha256:<64 hex>`: the image ID, from the `.imageid` sidecar.
    pub id: String,
    /// The tar's file name.
    pub artifact: String,
    pub arch: String,
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `(image, hex, arch)` of a rail tar name of `addon`'s, or `None` when the
/// name is not one.
pub fn parse_artifact(name: &str, addon: &str) -> Option<(String, String, String)> {
    let rest = name.strip_prefix(&format!("{ARTIFACT_PREFIX}{addon}_"))?.strip_suffix(".tar")?;
    let (rest, arch) = rest.rsplit_once('_')?;
    let (image, hex) = rest.rsplit_once('_')?;
    if image.is_empty() || !hex64(hex) || !matches!(arch, "amd64" | "arm64") {
        return None;
    }
    Some((image.to_string(), hex.to_string(), arch.to_string()))
}

/// The names of every image the rail holds for `addon` (any arch).
pub fn rail_image_names(dir: &Path, addon: &str) -> std::collections::BTreeSet<String> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Default::default() };
    rd.filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str().and_then(|n| parse_artifact(n, addon)).map(|(i, _, _)| i))
        .collect()
}

/// The ONE rail image for (`addon`, `image`, `arch`), with its sidecar ID.
pub fn rail_image(dir: &Path, addon: &str, image: &str, arch: &str) -> Result<RailImage, Refusal> {
    let missing = |why: String| Refusal::new(code::IMAGE_MISSING, why);
    let rd = std::fs::read_dir(dir).map_err(|e| missing(format!("the rail image directory {} cannot be read: {e}", dir.display())))?;
    let mut found: Vec<(String, String)> = Vec::new();
    for e in rd.filter_map(Result::ok) {
        let Some(name) = e.file_name().to_str().map(str::to_string) else { continue };
        if let Some((i, hex, a)) = parse_artifact(&name, addon) {
            if i == image && a == arch {
                found.push((name, hex));
            }
        }
    }
    let (artifact, hex) = match found.len() {
        1 => found.remove(0),
        0 => return Err(missing(format!("the rail holds no {arch} image {image:?} of {addon} (re-enable or upgrade the add-on)"))),
        n => {
            return Err(missing(format!(
                "the rail holds {n} {arch} images {image:?} of {addon}, so which one the lock names is not known (upgrade the add-on to prune)"
            )))
        }
    };
    let sidecar = dir.join(format!("{artifact}.imageid"));
    let id = match std::fs::metadata(&sidecar) {
        Ok(m) if m.is_file() && m.len() <= MAX_SIDECAR_BYTES => std::fs::read_to_string(&sidecar).map(|s| s.trim().to_string()).unwrap_or_default(),
        _ => String::new(),
    };
    if !id.strip_prefix("sha256:").is_some_and(hex64) {
        return Err(missing(format!("{artifact} has no valid .imageid sidecar (re-enable or upgrade the add-on)")));
    }
    let digest = format!("sha256:{hex}");
    if !crate::node_workloads::artifact_ok(&artifact, addon, image, &digest) {
        return Err(missing(format!("{artifact} is not the rail name for {addon} {image} {digest}")));
    }
    Ok(RailImage { image: image.to_string(), digest, id, artifact, arch: arch.to_string() })
}

/// `addon`'s node-workloads.json under `wl_dir`, validated, or `Ok(None)` when
/// it ships none. `routes_dir` holds its routes.json (`service_drain.route`
/// must be one of its internal routes); `images_dir` is the rail's image
/// directory, whose names stand in for the lock's image names: an image the
/// declaration names that the rail does not hold is `image_missing`.
pub fn read_decl(wl_dir: &Path, routes_dir: &Path, images_dir: &Path, addon: &str) -> Result<Option<NodeWorkloads>, Refusal> {
    if !crate::addon_registry::name_ok(addon) {
        return Err(Refusal::new(code::DECL_INVALID, format!("add-on name {addon:?} is not valid")));
    }
    let path = wl_dir.join(addon).join(NODE_WORKLOADS_FILE);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Refusal::new(code::DECL_INVALID, format!("{}: {e}", path.display()))),
    };
    if !meta.is_file() || meta.len() > MAX_DECL_BYTES {
        return Err(Refusal::new(code::DECL_INVALID, format!("{} is not a regular file of at most {MAX_DECL_BYTES} bytes", path.display())));
    }
    let bytes = std::fs::read(&path).map_err(|e| Refusal::new(code::DECL_INVALID, format!("{}: {e}", path.display())))?;
    let routes = match std::fs::read(routes_dir.join(addon).join(ROUTES_FILE)) {
        Ok(b) => Some(routes_from_json(&b).map_err(|e| Refusal::new(code::DECL_INVALID, format!("{addon}'s routes.json: {e}")))?),
        Err(_) => None,
    };
    let on_rail = rail_image_names(images_dir, addon);
    match validate_decl(&bytes, addon, &on_rail, routes.as_ref()) {
        Ok(d) => Ok(Some(d)),
        Err(r) if r.code == code::IMAGE_NOT_IN_LOCK => Err(Refusal::new(code::IMAGE_MISSING, format!("{r} (the rail holds no image by that name)"))),
        Err(r) => Err(r),
    }
}

/// The workload object `name` of `addon`'s delivered node-workloads.json,
/// exactly as the file carries it: desired-config's `decl` travels verbatim.
/// Call after [`read_decl`] validated the same file.
pub fn raw_workload(wl_dir: &Path, addon: &str, name: &str) -> Option<serde_json::Value> {
    if !crate::addon_registry::name_ok(addon) {
        return None;
    }
    let bytes = std::fs::read(wl_dir.join(addon).join(NODE_WORKLOADS_FILE)).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("workloads")?.as_array()?.iter().find(|w| w.get("name").and_then(|n| n.as_str()) == Some(name)).cloned()
}

/// Largest staged `model-set.json` read (the rail's cap).
const MAX_SET_MANIFEST_BYTES: u64 = 1 << 20;

/// A model set staged on the controller (`noo models stage`), validated, and
/// the total bytes of its files. A set is staged only once its detached
/// signature is there (the CLI writes it last); the node verifies the
/// signature itself. Not staged, or not a valid set of that id and revision:
/// `set_unverified`.
pub fn staged_set(sets_root: &Path, id: &str, revision: &str) -> Result<(crate::node_workloads::ModelSet, u64), Refusal> {
    let unverified = |why: String| Refusal::new(code::SET_UNVERIFIED, why);
    if !crate::node_workloads::valid_set_ref(id, revision) {
        return Err(unverified(format!("set {id:?}@{revision:?} is not a set name")));
    }
    let dir = sets_root.join(id).join(revision);
    if !dir.join("model-set.json.sig").is_file() {
        return Err(unverified(format!("set {id}@{revision} is not staged on the controller (noo models stage)")));
    }
    let path = dir.join("model-set.json");
    match std::fs::symlink_metadata(&path) {
        Ok(m) if m.is_file() && m.len() <= MAX_SET_MANIFEST_BYTES => {}
        _ => return Err(unverified(format!("set {id}@{revision}: model-set.json is missing or not a regular file"))),
    }
    let bytes = std::fs::read(&path).map_err(|e| unverified(format!("set {id}@{revision}: {e}")))?;
    let set = crate::node_workloads::validate_model_set(&bytes)
        .map_err(|r| unverified(format!("set {id}@{revision}: model-set.json is refused ({r})")))?;
    if set.id != id || set.revision != revision {
        return Err(unverified(format!("set {id}@{revision}: model-set.json names {}@{}", set.id, set.revision)));
    }
    let bytes: u64 = set.files.iter().map(|f| f.bytes.max(0) as u64).sum();
    Ok((set, bytes))
}

/// [`read_decl`] for a REGISTERED add-on, from the mounted directories;
/// `Ok(None)` for an add-on the registry does not register.
pub fn declared(addon: &str) -> Result<Option<NodeWorkloads>, Refusal> {
    if crate::addon_registry::get(addon).is_none() {
        return Ok(None);
    }
    read_decl(
        Path::new(crate::addon_decls::WORKLOADS_DIR),
        Path::new(crate::addon_proxy::BUNDLE_ROUTES_DIR),
        &crate::routes::artifacts::image_dir(),
        addon,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const ID: &str = "sha256:9999999999999999999999999999999999999999999999999999999999999999";

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-nw-sources-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn tar(dir: &Path, image: &str, hex: &str, arch: &str, id: Option<&str>) -> String {
        let name = format!("noo-addon-wl_rhaddon_{image}_{hex}_{arch}.tar");
        std::fs::write(dir.join(&name), b"tar").unwrap();
        if let Some(id) = id {
            std::fs::write(dir.join(format!("{name}.imageid")), format!("{id}\n")).unwrap();
        }
        name
    }

    #[test]
    fn a_rail_name_parses_into_image_hex_and_arch() {
        let n = format!("noo-addon-wl_rhaddon_addon-worker_{HEX}_amd64.tar");
        assert_eq!(parse_artifact(&n, "rhaddon"), Some(("addon-worker".into(), HEX.into(), "amd64".into())));
        assert_eq!(parse_artifact(&n, "other"), None, "another add-on's file");
        assert_eq!(parse_artifact(&format!("noo-addon-wl_rhaddon_w_{HEX}_riscv64.tar"), "rhaddon"), None);
        assert_eq!(parse_artifact(&format!("noo-addon-wl_rhaddon_w_{}_amd64.tar", &HEX[..63]), "rhaddon"), None);
        assert_eq!(parse_artifact(&format!("noo-addon-wl_rhaddon__{HEX}_amd64.tar"), "rhaddon"), None, "no image name");
        assert_eq!(parse_artifact(&format!("noo-addon-wl_rhaddon_w_{HEX}_amd64.tar.imageid"), "rhaddon"), None);
    }

    #[test]
    fn one_tar_with_its_sidecar_is_the_image() {
        let d = scratch("one");
        let name = tar(&d, "addon-worker", HEX, "amd64", Some(ID));
        tar(&d, "addon-worker", HEX, "arm64", Some(ID));
        let r = rail_image(&d, "rhaddon", "addon-worker", "amd64").unwrap();
        assert_eq!(r, RailImage { image: "addon-worker".into(), digest: format!("sha256:{HEX}"), id: ID.into(), artifact: name, arch: "amd64".into() });
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn no_tar_is_image_missing() {
        let d = scratch("none");
        tar(&d, "addon-worker", HEX, "arm64", Some(ID));
        let e = rail_image(&d, "rhaddon", "addon-worker", "amd64").unwrap_err();
        assert_eq!(e.code, code::IMAGE_MISSING);
        assert!(e.detail.contains("no amd64 image"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn several_tars_of_one_image_and_arch_are_image_missing_never_a_guess() {
        let d = scratch("several");
        tar(&d, "addon-worker", HEX, "amd64", Some(ID));
        tar(&d, "addon-worker", &"3".repeat(64), "amd64", Some(ID));
        let e = rail_image(&d, "rhaddon", "addon-worker", "amd64").unwrap_err();
        assert_eq!(e.code, code::IMAGE_MISSING);
        assert!(e.detail.contains("holds 2"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_missing_or_malformed_sidecar_is_image_missing() {
        let d = scratch("sidecar");
        tar(&d, "addon-worker", HEX, "amd64", None);
        assert_eq!(rail_image(&d, "rhaddon", "addon-worker", "amd64").unwrap_err().code, code::IMAGE_MISSING);
        for bad in ["sha256:abc", "9999999999999999999999999999999999999999999999999999999999999999", "sha256:ZZZZ999999999999999999999999999999999999999999999999999999999999", ""] {
            tar(&d, "addon-worker", HEX, "amd64", Some(bad));
            let e = rail_image(&d, "rhaddon", "addon-worker", "amd64").unwrap_err();
            assert_eq!(e.code, code::IMAGE_MISSING, "sidecar {bad:?}");
            assert!(e.detail.contains(".imageid"), "{e}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/testdata/i300").join(name)).unwrap()
    }

    /// The rhaddon fixture pair (node-workloads.json + routes.json) laid out
    /// as the launcher materialises it, with the rail holding its image.
    fn delivered(tag: &str, rail: bool) -> (PathBuf, PathBuf, PathBuf) {
        let root = scratch(tag);
        let (wl, rt, img) = (root.join("wl"), root.join("rt"), root.join("img"));
        for d in [&wl, &rt, &img] {
            std::fs::create_dir_all(d.join("rhaddon")).unwrap();
        }
        std::fs::write(wl.join("rhaddon").join(NODE_WORKLOADS_FILE), fixture("node-workloads/valid-rhaddon.json")).unwrap();
        std::fs::write(rt.join("rhaddon").join(ROUTES_FILE), fixture("node-workloads/routes.json")).unwrap();
        if rail {
            for image in crate::node_workloads::validate_decl(&fixture("node-workloads/valid-rhaddon.json"), "rhaddon", &lock_names(), Some(&routes()))
                .unwrap()
                .workloads
                .iter()
                .map(|w| w.image.clone())
            {
                tar(&img, &image, HEX, "amd64", Some(ID));
            }
        }
        (wl, rt, img)
    }

    fn lock_names() -> std::collections::BTreeSet<String> {
        let v: serde_json::Value = serde_json::from_slice(&fixture("node-workloads/lock.json")).unwrap();
        v["images"].as_object().unwrap().keys().cloned().collect()
    }

    fn routes() -> crate::node_workloads::Routes {
        routes_from_json(&fixture("node-workloads/routes.json")).unwrap()
    }

    #[test]
    fn a_delivered_declaration_reads_and_validates() {
        let (wl, rt, img) = delivered("decl-ok", true);
        let d = read_decl(&wl, &rt, &img, "rhaddon").unwrap().expect("declared");
        assert!(!d.workloads.is_empty());
        let _ = std::fs::remove_dir_all(wl.parent().unwrap());
    }

    #[test]
    fn no_file_is_no_declaration_and_a_bad_name_is_refused() {
        let (wl, rt, img) = delivered("decl-none", true);
        assert_eq!(read_decl(&wl, &rt, &img, "otheraddon").unwrap(), None);
        assert_eq!(read_decl(&wl, &rt, &img, "../rhaddon").unwrap_err().code, code::DECL_INVALID);
        let _ = std::fs::remove_dir_all(wl.parent().unwrap());
    }

    #[test]
    fn a_declared_image_the_rail_does_not_hold_is_image_missing() {
        let (wl, rt, img) = delivered("decl-norail", false);
        assert_eq!(read_decl(&wl, &rt, &img, "rhaddon").unwrap_err().code, code::IMAGE_MISSING);
        let _ = std::fs::remove_dir_all(wl.parent().unwrap());
    }

    const SET_ID: &str = "rh-s2s-7b";
    const SET_REV: &str = "0123456789abcdef0123456789abcdef01234567";

    /// The valid-voice fixture staged as `noo models stage` leaves it.
    fn staged(tag: &str, sig: bool) -> PathBuf {
        let root = scratch(tag);
        let d = root.join(SET_ID).join(SET_REV);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("model-set.json"), fixture("model-sets/valid-voice.json")).unwrap();
        if sig {
            std::fs::write(d.join("model-set.json.sig"), b"sig").unwrap();
        }
        root
    }

    #[test]
    fn a_staged_signed_set_validates_and_is_sized() {
        let root = staged("set-ok", true);
        let (set, bytes) = staged_set(&root, SET_ID, SET_REV).unwrap();
        assert_eq!((set.id.as_str(), set.revision.as_str()), (SET_ID, SET_REV));
        assert_eq!(bytes, 15_600_574_336, "the sum of its files' bytes");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_set_without_its_signature_is_not_staged() {
        let root = staged("set-nosig", false);
        let e = staged_set(&root, SET_ID, SET_REV).unwrap_err();
        assert_eq!(e.code, code::SET_UNVERIFIED);
        assert!(e.detail.contains("not staged"), "{e}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_set_name_that_is_not_one_never_reaches_the_filesystem() {
        let root = staged("set-names", true);
        for (id, rev) in [("../rh-s2s-7b", SET_REV), (SET_ID, "../x"), ("..", SET_REV), (SET_ID, "")] {
            let e = staged_set(&root, id, rev).unwrap_err();
            assert_eq!(e.code, code::SET_UNVERIFIED);
            assert!(e.detail.contains("is not a set name"), "{id:?} {rev:?}: {e}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_manifest_naming_another_set_is_refused() {
        let root = staged("set-other", true);
        let other = root.join("rh-other").join(SET_REV);
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("model-set.json"), fixture("model-sets/valid-voice.json")).unwrap();
        std::fs::write(other.join("model-set.json.sig"), b"sig").unwrap();
        let e = staged_set(&root, "rh-other", SET_REV).unwrap_err();
        assert_eq!(e.code, code::SET_UNVERIFIED);
        assert!(e.detail.contains("names rh-s2s-7b"), "{e}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_raw_workload_is_the_files_object_verbatim() {
        let (wl, _rt, _img) = delivered("raw", true);
        let file: serde_json::Value = serde_json::from_slice(&fixture("node-workloads/valid-rhaddon.json")).unwrap();
        let name = file["workloads"][0]["name"].as_str().unwrap();
        assert_eq!(raw_workload(&wl, "rhaddon", name), Some(file["workloads"][0].clone()));
        assert_eq!(raw_workload(&wl, "rhaddon", "nope"), None);
        assert_eq!(raw_workload(&wl, "../rhaddon", name), None);
        let _ = std::fs::remove_dir_all(wl.parent().unwrap());
    }

    /// The launcher copies a regular file; a symlink in its place (even to a
    /// valid declaration) is not what it delivered and is refused, never
    /// followed.
    #[test]
    fn a_declaration_that_is_not_a_regular_file_is_refused() {
        let (wl, rt, img) = delivered("decl-link", true);
        let p = wl.join("rhaddon").join(NODE_WORKLOADS_FILE);
        let real = wl.join("elsewhere.json");
        std::fs::rename(&p, &real).unwrap();
        std::os::unix::fs::symlink(&real, &p).unwrap();
        assert_eq!(read_decl(&wl, &rt, &img, "rhaddon").unwrap_err().code, code::DECL_INVALID);
        let _ = std::fs::remove_dir_all(wl.parent().unwrap());
    }
}
