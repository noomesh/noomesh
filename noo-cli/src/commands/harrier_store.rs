// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! harrier, the default embedder: its fetch, its checks, and its copy in the
//! controller's model store.
//!
//! The finding this answers. During a stack restart the embedder's fetch got
//! ONE `received unexpected HTTP status: 500 Internal Server Error` from the
//! registry (fine minutes later). The fetch made one attempt and gave up; the
//! restore's `noo models pull harrier` hit the same 500; and no node agent
//! could heal it (`ollama_registry_pull_refused: harrier …`), because harrier
//! was not in the controller's store. One transient registry error left RAG
//! embedding down until a human acted.
//!
//! The rules here:
//! - **Retry only the transient.** The `docker pull` of `harrier@<digest>` is
//!   retried on a registry 5xx or 429, a timeout, a reset or a refused
//!   connection ([`crate::release_fetch::classify_docker_pull`] reads the
//!   typed status out of docker's error format), on the bounded schedule
//!   [`PULL_BACKOFF`]. A 401/403/404, a digest mismatch or anything else
//!   unrecognised fails at once; a checksum failure is never retried either
//!   (it is checked after the pull, on the files).
//! - **The lock decides, never the network.** A pair is CHECKED when
//!   `sha256sum -c harrier.sha256` passes AND the GGUF's sha256 equals the
//!   signed stack lock's `# harrier-gguf-sha256` ([`verify_unpacked`]); the
//!   image's own sum file travels with the image, so it alone is not the
//!   release's word.
//! - **A checked pair goes into the store** ([`place_in_store`]), laid out as
//!   `noo cluster import-model` expects (`harrier.Modelfile` with a bare
//!   `FROM harrier-Q4_K_M.gguf`, the weight, `harrier.sha256`), with a record
//!   of the image digest it came from ([`PIN_RECORD`]). Nodes then import
//!   harrier from the store like any published model, and the controller's
//!   own fetch has a fallback.
//! - **The store copy is a fallback only for an unreachable registry**, and
//!   only when its record names the lock's image digest and its GGUF is the
//!   lock's ([`store_copy_usable`]). A copy for another digest or GGUF is
//!   never used.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::release_fetch::{classify_docker_pull, FetchClass};

/// The weight the artifact carries (the name its sum file and Modelfile use).
pub(crate) const GGUF: &str = "harrier-Q4_K_M.gguf";
/// The recipe, beside its weight.
pub(crate) const MODELFILE: &str = "harrier.Modelfile";
/// Which artifact the store's pair came from: written last by
/// [`place_in_store`], only for a pair the lock vouched for, and removed
/// first when a pair is replaced, so a half-replaced pair has none. Not a
/// `.gguf` or `.modelfile`, so the gateway's manifest route never serves it.
pub(crate) const PIN_RECORD: &str = "harrier.artifact-pin";

/// Waits between the tries of a transient pull failure: 5 tries in all, at
/// most 90 s of waiting. A 429 waits the same (docker hides any Retry-After).
pub(crate) const PULL_BACKOFF: [Duration; 4] =
    [Duration::from_secs(5), Duration::from_secs(15), Duration::from_secs(30), Duration::from_secs(40)];

/// What this host's signed stack lock pins harrier to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HarrierPin {
    /// `<prefix>/harrier@sha256:…`, the only thing ever pulled.
    pub reference: String,
    /// `sha256:…`, the artifact image.
    pub image: String,
    /// `sha256:…`, the GGUF the lock vouches for; None for a lock without
    /// the `# harrier-gguf-sha256` line (no release writes one).
    pub gguf: Option<String>,
}

/// The controller's model store: `MODELS_DIR`, else `<NOO_DATA_ROOT>/models`
/// (the process env, else this install's `.env`), as `noo cluster
/// import-model` and the gateway's `/artifacts/models` mount resolve it.
pub(crate) fn store_dir() -> PathBuf {
    let m = crate::commands::provision::release_var("MODELS_DIR");
    let r = crate::commands::provision::release_var("NOO_DATA_ROOT");
    PathBuf::from(crate::commands::models_fetch::store_dir_from(Some(m.as_str()), Some(r.as_str())))
}

// ── The pull ────────────────────────────────────────────────────────────

/// Why a pull failed for good.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PullFailure {
    pub class: FetchClass,
    pub status: Option<u16>,
    /// docker's last error line.
    pub detail: String,
    pub tries: usize,
}

impl std::fmt::Display for PullFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tries = if self.tries == 1 { "1 try".to_string() } else { format!("{} tries", self.tries) };
        let status = self.status.map(|c| format!(" (HTTP {c})")).unwrap_or_default();
        write!(f, "{}{status} after {tries}: {}", self.class.label(), self.detail)
    }
}

/// What one transient failure was, for the retry line: "ghcr.io answered
/// 500", or "ghcr.io: network error". Pure.
pub(crate) fn transient_what(registry: &str, class: FetchClass, status: Option<u16>) -> String {
    match status {
        Some(code) => format!("{registry} answered {code}"),
        None => format!("{registry}: {}", class.label()),
    }
}

/// The pull, retried on [`PULL_BACKOFF`] while it fails transiently. `pull`
/// returns docker's stderr on a failure; `say` gets one line per retry
/// ("ghcr.io answered 500; retrying in 15 s (2 of 4)"). Pure over its
/// closures.
pub(crate) fn pull_with_retry(
    registry: &str,
    pull: &mut dyn FnMut() -> Result<(), String>,
    sleep: &mut dyn FnMut(Duration),
    say: &mut dyn FnMut(String),
) -> Result<(), PullFailure> {
    let mut tries = 0usize;
    loop {
        tries += 1;
        let stderr = match pull() {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        let (class, status) = classify_docker_pull(&stderr);
        let retry = tries - 1;
        if !class.transient() || retry >= PULL_BACKOFF.len() {
            let detail = stderr.lines().map(str::trim).rfind(|l| !l.is_empty()).unwrap_or("(no output)").to_string();
            return Err(PullFailure { class, status, detail, tries });
        }
        let wait = PULL_BACKOFF[retry];
        say(format!(
            "{}; retrying in {} s ({} of {})",
            transient_what(registry, class, status),
            wait.as_secs(),
            retry + 1,
            PULL_BACKOFF.len()
        ));
        sleep(wait);
    }
}

/// One quiet `docker pull <reference>`: docker's stderr on a failure.
fn docker_pull_once(reference: &str) -> Result<(), String> {
    let o = Command::new("docker")
        .args(["pull", "-q", reference])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run docker: {e}"))?;
    if o.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&o.stderr).into_owned())
    }
}

/// Pull the pinned artifact, retrying the transient ([`pull_with_retry`]).
pub(crate) fn pull(reference: &str, say: &mut dyn FnMut(String)) -> Result<(), PullFailure> {
    let registry = reference.split('/').next().unwrap_or(reference);
    pull_with_retry(registry, &mut || docker_pull_once(reference), &mut crate::release_fetch::real_sleep, say)
}

/// `docker create` + `docker cp` the pulled artifact's files (`/harrier/`)
/// into `into`. The image is already local: nothing here reaches a registry.
pub(crate) fn unpack(reference: &str, into: &Path) -> bool {
    let src = format!("noo-harrier-src-{}", std::process::id());
    Command::new("bash")
        .arg("-c")
        .arg(format!(
            "docker rm -f '{src}' >/dev/null 2>&1; \
             docker create --name '{src}' '{reference}' >/dev/null && \
             docker cp '{src}:/harrier/.' '{d}/'; rc=$?; docker rm -f '{src}' >/dev/null 2>&1; exit $rc",
            d = into.display()
        ))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ── The checks ──────────────────────────────────────────────────────────

/// The GGUF's sha256 against the lock's `# harrier-gguf-sha256`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockGguf {
    Matches,
    Differs,
    /// The lock carries no GGUF line: only the image's sum file vouches.
    NotInLock,
}

/// `got` and `lock` are `sha256:<hex>`. Pure.
pub(crate) fn gguf_against_lock(got: &str, lock: Option<&str>) -> LockGguf {
    match lock {
        None => LockGguf::NotInLock,
        Some(l) if l.eq_ignore_ascii_case(got) => LockGguf::Matches,
        Some(_) => LockGguf::Differs,
    }
}

/// What a check of a pair proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Checked {
    /// `sha256:…` of the GGUF.
    pub gguf: String,
    /// The lock's GGUF line named exactly this file.
    pub lock_vouches: bool,
}

fn sha256_of(path: &Path) -> Result<String, String> {
    crate::commands::models_fetch::sha256_file(path)
        .map(|h| format!("sha256:{h}"))
        .map_err(|e| format!("cannot hash {}: {e}", path.display()))
}

/// The unpacked artifact in `dir`: `sha256sum -c harrier.sha256` passes, and
/// the GGUF is the one the lock vouches for. A sum-file mismatch or a GGUF
/// the lock does not name refuses.
pub(crate) fn verify_unpacked(dir: &Path, lock_gguf: Option<&str>) -> Result<Checked, String> {
    if !crate::onboard::steps::artifact_sha256_ok(dir, "harrier") {
        return Err("the unpacked files do not match its harrier.sha256 — refusing them".into());
    }
    let got = sha256_of(&dir.join(GGUF))?;
    match gguf_against_lock(&got, lock_gguf) {
        LockGguf::Matches => Ok(Checked { gguf: got, lock_vouches: true }),
        LockGguf::NotInLock => Ok(Checked { gguf: got, lock_vouches: false }),
        LockGguf::Differs => Err(format!(
            "{GGUF} is {got}, but the signed stack lock vouches for {} — refusing it",
            lock_gguf.unwrap_or_default()
        )),
    }
}

// ── The store ───────────────────────────────────────────────────────────

/// The Modelfile as the store holds it: `FROM ./x.gguf` becomes `FROM
/// x.gguf`, the bare name the agent's importer requires. Pure.
pub(crate) fn modelfile_for_store(body: &str) -> String {
    body.lines()
        .map(|l| match l.strip_prefix("FROM ./") {
            Some(rest) => format!("FROM {rest}"),
            None => l.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// The record of where the store's pair came from. Pure.
pub(crate) fn pin_record(image: &str, gguf: &str, modelfile: &str) -> String {
    format!("image {image}\ngguf {gguf}\nmodelfile {modelfile}\n")
}

/// `(image, gguf, modelfile)` from a [`pin_record`]; None when any is
/// missing. Pure.
pub(crate) fn parse_pin_record(text: &str) -> Option<(String, String, String)> {
    let field = |k: &str| {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(k)?.strip_prefix(' ').map(|v| v.trim().to_string()))
            .filter(|v| v.starts_with("sha256:"))
    };
    Some((field("image")?, field("gguf")?, field("modelfile")?))
}

/// `src` at `dst`: a hard link when both are on one filesystem (the private
/// temp dir and the store usually are), else a copy. Either way the store
/// then holds one more copy of the GGUF, about 0.4 GB of disk, for as long as
/// it holds harrier; a copy also costs that much again until the temp dir
/// is removed.
fn link_or_copy(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::hard_link(src, dst).or_else(|_| std::fs::copy(src, dst).map(|_| ()))
}

/// Put a CHECKED pair from `from` into `store`, laid out as `noo cluster
/// import-model` (and the agent behind it) expects: every file under its own
/// name, the Modelfile with a bare `FROM`. Each file lands as `<name>.publishing`
/// and is renamed over the old one (the gateway keys its digest cache on
/// size, mtime and inode: a half-written file is never hashed as truth).
/// The [`PIN_RECORD`] is removed first and written last, and only when the
/// lock vouched for the GGUF. `image` is the lock's artifact digest. Returns
/// the file names placed (the record not among them).
pub(crate) fn place_in_store(from: &Path, store: &Path, image: &str, checked: &Checked) -> Result<Vec<String>, String> {
    std::fs::create_dir_all(store).map_err(|e| format!("create {}: {e}", store.display()))?;
    let record = store.join(PIN_RECORD);
    match std::fs::remove_file(&record) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("remove {}: {e}", record.display())),
    }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(from).map_err(|e| format!("read {}: {e}", from.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.path().is_file() {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    names.sort();
    for fname in &names {
        let src = from.join(fname);
        let part = store.join(format!("{fname}.publishing"));
        let _ = std::fs::remove_file(&part);
        if fname.to_ascii_lowercase().ends_with(".modelfile") {
            let body = std::fs::read_to_string(&src).map_err(|e| format!("read {fname}: {e}"))?;
            std::fs::write(&part, modelfile_for_store(&body)).map_err(|e| format!("write {fname}: {e}"))?;
        } else {
            link_or_copy(&src, &part).map_err(|e| format!("copy {fname}: {e}"))?;
        }
        std::fs::rename(&part, store.join(fname)).map_err(|e| format!("finalize {fname}: {e}"))?;
        // rename(2) does nothing when both names are links to one file (the
        // same pair placed again by hard link): the part name goes here.
        let _ = std::fs::remove_file(&part);
    }
    if checked.lock_vouches {
        let mf = sha256_of(&store.join(MODELFILE))?;
        let part = store.join(format!("{PIN_RECORD}.publishing"));
        std::fs::write(&part, pin_record(image, &checked.gguf, &mf)).map_err(|e| format!("write {PIN_RECORD}: {e}"))?;
        std::fs::rename(&part, &record).map_err(|e| format!("finalize {PIN_RECORD}: {e}"))?;
    }
    Ok(names)
}

/// Why a store copy without a [`PIN_RECORD`] is never used.
const NO_RECORD: &str = "the store's copy has no record of the artifact it came from";

/// May the store's copy stand in for the registry? Only when its record
/// names the lock's image digest and GGUF, and the copy's GGUF and Modelfile
/// hash to what was recorded: the lock decides, never the network. `record`
/// is the [`PIN_RECORD`] text (None: absent); `gguf` and `modelfile` are the
/// sha256 of the copies about to be used. Pure.
pub(crate) fn store_copy_usable(record: Option<&str>, pin: &HarrierPin, gguf: &str, modelfile: &str) -> Result<(), String> {
    let record = record.ok_or(NO_RECORD)?;
    let (r_image, r_gguf, r_mf) = parse_pin_record(record).ok_or("the store's record of its artifact is unreadable")?;
    if r_image != pin.image {
        return Err(format!("the store's copy came from {r_image}, and the lock pins {}", pin.image));
    }
    let lock_gguf = pin.gguf.as_deref().ok_or("the lock vouches for no GGUF")?;
    if !r_gguf.eq_ignore_ascii_case(lock_gguf) || gguf_against_lock(gguf, Some(lock_gguf)) != LockGguf::Matches {
        return Err(format!("the store's {GGUF} is {gguf}, and the lock vouches for {lock_gguf}"));
    }
    if !r_mf.eq_ignore_ascii_case(modelfile) {
        return Err(format!("the store's {MODELFILE} is not the one placed with it"));
    }
    Ok(())
}

/// Copy the store's pair into `into` (the bytes checked are the bytes then
/// used, whatever happens to the store meanwhile) and decide with
/// [`store_copy_usable`]. Ok: `into` holds a checked pair.
pub(crate) fn take_store_copy(store: &Path, pin: &HarrierPin, into: &Path) -> Result<Checked, String> {
    let record = match std::fs::read_to_string(store.join(PIN_RECORD)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(NO_RECORD.to_string()),
        Err(e) => return Err(format!("cannot read {}: {e}", store.join(PIN_RECORD).display())),
    };
    for f in [GGUF, MODELFILE] {
        std::fs::copy(store.join(f), into.join(f)).map_err(|e| format!("cannot copy the store's {f}: {e}"))?;
    }
    let gguf = sha256_of(&into.join(GGUF))?;
    let mf = sha256_of(&into.join(MODELFILE))?;
    store_copy_usable(Some(record.as_str()), pin, &gguf, &mf)?;
    Ok(Checked { gguf, lock_vouches: true })
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMG: &str = "sha256:2fe41964a009bda0c55f299b632b122bcb4561ca4a833e3293c9f3cc685bab79";

    fn pin(gguf: &str) -> HarrierPin {
        HarrierPin { reference: format!("ghcr.io/noomesh/harrier@{IMG}"), image: IMG.into(), gguf: Some(gguf.into()) }
    }

    fn sha(b: &[u8]) -> String {
        format!("sha256:{}", crate::addons::pins::sha256_hex(b))
    }

    /// A fresh scratch dir for one test.
    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-harrier-store-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The artifact's three files, as `docker cp` unpacks them.
    fn unpacked(dir: &Path, gguf: &[u8]) {
        std::fs::write(dir.join(GGUF), gguf).unwrap();
        std::fs::write(dir.join(MODELFILE), "FROM ./harrier-Q4_K_M.gguf\nPARAMETER num_ctx 8192\n").unwrap();
        std::fs::write(dir.join("harrier.sha256"), format!("{}  {GGUF}\n", crate::addons::pins::sha256_hex(gguf))).unwrap();
    }

    /// A scripted run: the outcome, the waits, the lines said, the tries.
    type Run = (Result<(), PullFailure>, Vec<Duration>, Vec<String>, usize);

    fn sleeps_and_lines(script: &[&str]) -> Run {
        let mut n = 0usize;
        let (mut sleeps, mut lines) = (Vec::new(), Vec::new());
        let r = pull_with_retry(
            "ghcr.io",
            &mut || {
                let out = script[n.min(script.len() - 1)];
                n += 1;
                if out.is_empty() { Ok(()) } else { Err(out.to_string()) }
            },
            &mut |d| sleeps.push(d),
            &mut |l| lines.push(l),
        );
        (r, sleeps, lines, n)
    }

    const E500: &str = "Error response from daemon: received unexpected HTTP status: 500 Internal Server Error";
    const E404: &str = "Error response from daemon: received unexpected HTTP status: 404 Not Found";

    /// The finding: one 500, then the registry is fine. The pull is retried
    /// and says why.
    #[test]
    fn one_500_is_retried_and_said() {
        let (r, sleeps, lines, n) = sleeps_and_lines(&[E500, ""]);
        assert!(r.is_ok());
        assert_eq!(n, 2);
        assert_eq!(sleeps, vec![Duration::from_secs(5)]);
        assert_eq!(lines, vec!["ghcr.io answered 500; retrying in 5 s (1 of 4)".to_string()]);
    }

    /// A 404 is not retried.
    #[test]
    fn a_404_fails_at_once() {
        let (r, sleeps, _, n) = sleeps_and_lines(&[E404]);
        let f = r.unwrap_err();
        assert_eq!((f.class, f.status, f.tries, n), (FetchClass::NotFound, Some(404), 1, 1));
        assert!(sleeps.is_empty());
    }

    /// The schedule is bounded: 5 tries, 4 waits, 90 s at most.
    #[test]
    fn the_backoff_is_bounded() {
        let (r, sleeps, lines, n) = sleeps_and_lines(&[E500]);
        let f = r.unwrap_err();
        assert_eq!((n, f.tries), (5, 5));
        assert_eq!(sleeps, PULL_BACKOFF.to_vec());
        assert!(sleeps.iter().sum::<Duration>() <= Duration::from_secs(90));
        assert_eq!(lines[1], "ghcr.io answered 500; retrying in 15 s (2 of 4)");
        assert_eq!(f.class, FetchClass::Server);
        assert!(f.to_string().starts_with("server error (HTTP 500) after 5 tries: "), "{f}");
    }

    /// The lock's GGUF line decides, not the image's own sum file.
    #[test]
    fn the_gguf_is_checked_against_the_lock_line() {
        let d = scratch("verify");
        unpacked(&d, b"GGUFweights");
        let good = sha(b"GGUFweights");
        assert_eq!(verify_unpacked(&d, Some(good.as_str())).unwrap(), Checked { gguf: good.clone(), lock_vouches: true });
        // The sum file agrees with the bytes, and the lock names another GGUF.
        let other = sha(b"other");
        let e = verify_unpacked(&d, Some(other.as_str())).unwrap_err();
        assert!(e.contains("the signed stack lock vouches for"), "{e}");
        // No GGUF line in the lock: the sum file passes, and the lock vouches for nothing.
        assert!(!verify_unpacked(&d, None).unwrap().lock_vouches);
        let upper = good.to_ascii_uppercase().replace("SHA256:", "sha256:");
        assert_eq!(gguf_against_lock(&good, Some(upper.as_str())), LockGguf::Matches);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The store layout is `import-model`'s: the three files by name, the
    /// Modelfile with a bare FROM, and the record of the image last.
    #[test]
    fn the_store_layout_is_import_models() {
        let (d, store) = (scratch("layout-src"), scratch("layout-store"));
        unpacked(&d, b"GGUFweights");
        let g = sha(b"GGUFweights");
        let checked = verify_unpacked(&d, Some(g.as_str())).unwrap();
        let got = place_in_store(&d, &store, IMG, &checked).unwrap();
        assert_eq!(got, ["harrier-Q4_K_M.gguf", "harrier.Modelfile", "harrier.sha256"]);
        let mf = std::fs::read_to_string(store.join(MODELFILE)).unwrap();
        assert_eq!(mf, "FROM harrier-Q4_K_M.gguf\nPARAMETER num_ctx 8192\n");
        assert_eq!(std::fs::read(store.join(GGUF)).unwrap(), b"GGUFweights");
        let rec = std::fs::read_to_string(store.join(PIN_RECORD)).unwrap();
        assert_eq!(rec, pin_record(IMG, &sha(b"GGUFweights"), &sha(mf.as_bytes())));
        assert!(!std::fs::read_dir(&store).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().ends_with(".publishing")));
        // A pair the lock did not vouch for is placed without a record, and
        // the old record does not survive it.
        let unvouched = Checked { gguf: checked.gguf, lock_vouches: false };
        place_in_store(&d, &store, IMG, &unvouched).unwrap();
        assert!(!store.join(PIN_RECORD).exists());
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&store);
    }

    /// The fallback rule: the same digest and GGUF → use; anything else, or
    /// no record → refuse.
    #[test]
    fn the_store_fallback_follows_the_lock() {
        let (g, m) = (sha(b"GGUFweights"), sha(b"FROM harrier-Q4_K_M.gguf\n"));
        let rec = pin_record(IMG, &g, &m);
        let p = pin(&g);
        assert_eq!(store_copy_usable(Some(rec.as_str()), &p, &g, &m), Ok(()));
        // Another digest.
        let other = pin_record("sha256:0000000000000000000000000000000000000000000000000000000000000000", &g, &m);
        assert!(store_copy_usable(Some(other.as_str()), &p, &g, &m).unwrap_err().contains("and the lock pins"));
        // The copy's GGUF is not the lock's (tampered, or a later release's lock).
        assert!(store_copy_usable(Some(rec.as_str()), &p, &sha(b"x"), &m).unwrap_err().contains("the lock vouches for"));
        assert!(store_copy_usable(Some(rec.as_str()), &pin(&sha(b"x")), &g, &m).is_err());
        // No record.
        assert!(store_copy_usable(None, &p, &g, &m).unwrap_err().contains("no record"));
        // A lock without the GGUF line vouches for nothing.
        let mut nogguf = p.clone();
        nogguf.gguf = None;
        assert!(store_copy_usable(Some(rec.as_str()), &nogguf, &g, &m).is_err());
        // A Modelfile not the one placed.
        assert!(store_copy_usable(Some(rec.as_str()), &p, &g, &sha(b"FROM other.gguf\n")).is_err());
    }

    /// The whole round: a checked pair placed, then taken back as the
    /// fallback; a store copy under another lock is refused.
    #[test]
    fn a_placed_pair_is_taken_back_only_under_its_lock() {
        let (d, store, into) = (scratch("rt-src"), scratch("rt-store"), scratch("rt-into"));
        unpacked(&d, b"GGUFweights");
        let g = sha(b"GGUFweights");
        place_in_store(&d, &store, IMG, &verify_unpacked(&d, Some(g.as_str())).unwrap()).unwrap();
        assert_eq!(take_store_copy(&store, &pin(&g), &into).unwrap(), Checked { gguf: g, lock_vouches: true });
        assert!(take_store_copy(&store, &pin(&sha(b"next release")), &into).is_err());
        std::fs::remove_file(store.join(PIN_RECORD)).unwrap();
        assert!(take_store_copy(&store, &pin(&sha(b"GGUFweights")), &into).unwrap_err().contains("no record"));
        for x in [d, store, into] {
            let _ = std::fs::remove_dir_all(x);
        }
    }

    #[test]
    fn a_pin_record_round_trips() {
        let r = pin_record(IMG, "sha256:aa", "sha256:bb");
        assert_eq!(parse_pin_record(&r), Some((IMG.to_string(), "sha256:aa".to_string(), "sha256:bb".to_string())));
        assert_eq!(parse_pin_record("image sha256:aa\n"), None);
    }
}
