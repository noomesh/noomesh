// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Publish an add-on's signed lock to its own registry package: the push
//! half of [`super::lock_fetch`], for `noo security addon-lock publish`.
//!
//! The artifact is exactly what `lock_fetch` reads (and what the `oras push`
//! recipe in docs/development/addons.md produces): one OCI image manifest of
//! artifactType [`ARTIFACT_TYPE`] with the empty config, and the layers, in
//! order, the v1 pair ([`LOCK_TITLE`], [`SIG_TITLE`]) when the developer
//! signed one, the bundle pair ([`BUNDLE_TITLE`], [`BUNDLE_SIG_TITLE`]) and
//! one [`FILE_MEDIA_TYPE`] layer per file the bundle lists, each titled
//! (`org.opencontainers.image.title`). The same manifest is pushed under
//! `stack-<tag>` for every tag the lock's `supports_stack` lists.
//!
//! The flow is the OCI distribution push API:
//!   1. per blob, `HEAD /v2/<path>/blobs/<digest>`; when absent,
//!      `POST /v2/<path>/blobs/uploads/` and `PUT <Location>?digest=<digest>`
//!      (one monolithic upload; the Location may be relative or absolute, and
//!      an absolute one must stay on the registry);
//!   2. per tag, `PUT /v2/<path>/manifests/stack-<tag>`;
//!   3. per tag, the artifact is read back through `lock_fetch` (the code
//!      every upgrade runs) and must return the very bytes pushed: a publish
//!      that an upgrade could not read fails here, at the publisher.
//!
//! Auth: a 401 carries a challenge. A Bearer challenge is answered at its
//! realm (https, on the registry host, as `lock_fetch` requires) with Basic
//! `<user>:<token>`, asking for `repository:<path>:pull,push`; a Basic
//! challenge is answered with the credential directly. The token never
//! enters an error or an output line: every error passes through
//! [`crate::release_fetch::redact`] and [`scrub`].
//!
//! Nothing here signs. The bundle and its signature are what
//! `noo security addon-lock sign` wrote; this checks that they form an
//! artifact a controller would read (canonical v2 lock, files present and
//! hashing to the lock, every layer under [`MAX_BLOB`]) and publishes it.

use std::cell::RefCell;
use std::collections::BTreeMap;

use super::lock_fetch::{
    self, Credential, ARTIFACT_TYPE, BUNDLE_MEDIA_TYPE, BUNDLE_SIG_TITLE, BUNDLE_TITLE, FILE_MEDIA_TYPE, LOCK_MEDIA_TYPE,
    LOCK_TITLE, MANIFEST_ACCEPT, MAX_BLOB, MAX_FILES, SIG_MEDIA_TYPE, SIG_TITLE, TITLE_ANNOTATION,
};
use crate::addon_lock::{self, AddonLock};
use crate::release_fetch::{self, FetchClass, FetchError};

/// The OCI empty config an artifact manifest carries (as oras pushes it).
pub const EMPTY_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";
/// Its two bytes.
pub const EMPTY_CONFIG: &[u8] = b"{}";

/// One blob of the artifact: a layer, or the config (no title).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    pub title: Option<String>,
    pub media_type: &'static str,
    pub digest: String,
    pub bytes: Vec<u8>,
}

impl Blob {
    fn new(title: Option<&str>, media_type: &'static str, bytes: Vec<u8>) -> Blob {
        Blob { title: title.map(str::to_string), media_type, digest: addon_lock::sha256_ref(&bytes), bytes }
    }

    /// `{title, media_type, size, digest}`, for `--dry-run` and `--json`.
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({"title": self.title.as_deref().unwrap_or("(config)"), "media_type": self.media_type,
            "size": self.bytes.len(), "digest": self.digest})
    }
}

/// What the developer hands over: the bundle lock and its `.sig`, the v1
/// pair when one was signed, and the bundle's files by name.
#[derive(Debug, Clone, Default)]
pub struct Inputs {
    pub bundle: Vec<u8>,
    pub bundle_sig: String,
    pub v1: Option<(Vec<u8>, String)>,
    pub files: BTreeMap<String, Vec<u8>>,
}

/// The artifact to publish: one manifest, pushed under every tag.
#[derive(Debug, Clone)]
pub struct Plan {
    pub addon: String,
    pub version: String,
    /// The stack tags (`v0.6.24`), from `supports_stack`.
    pub tags: Vec<String>,
    pub config: Blob,
    pub layers: Vec<Blob>,
    pub manifest: Vec<u8>,
    pub manifest_digest: String,
    /// What a read-back must return.
    bundle: Vec<u8>,
    bundle_sig: String,
    files: BTreeMap<String, Vec<u8>>,
}

/// The layer titles the artifact reserves; no bundle file may take one.
const RESERVED_TITLES: [&str; 4] = [LOCK_TITLE, SIG_TITLE, BUNDLE_TITLE, BUNDLE_SIG_TITLE];

/// Check the inputs form an artifact a controller reads, and lay it out.
/// `root` is the registry root the images must sit under.
pub fn plan(inputs: Inputs, root: &str) -> Result<Plan, String> {
    let Inputs { bundle, bundle_sig, v1, files } = inputs;
    let lock: AddonLock = serde_json::from_slice(&bundle).map_err(|e| format!("{BUNDLE_TITLE} is not an add-on lock: {e}"))?;
    if lock.format != addon_lock::FORMAT_V2 {
        return Err(format!(
            "the bundle lock is format {}, not {}: sign it with one --file <name>=<path> per file the add-on ships",
            lock.format,
            addon_lock::FORMAT_V2
        ));
    }
    if lock.canonical_bytes() != bundle {
        return Err("the bundle lock is not in canonical form (was it re-serialised?); publish the bytes sign wrote".into());
    }
    lock.validate(&lock.addon, Some(root)).map_err(|e| format!("the bundle lock would be refused: {e}"))?;
    if !bundle_sig.trim().starts_with(crate::release_sig::SIG_PREFIX) {
        return Err(format!("{BUNDLE_SIG_TITLE} is not a noo-sig1 signature (is it the .sig sign wrote?)"));
    }
    if files.len() > MAX_FILES {
        return Err(format!("the bundle lists {} files; a controller reads at most {MAX_FILES}", files.len()));
    }
    if let Some(name) = files.keys().find(|n| RESERVED_TITLES.contains(&n.as_str())) {
        return Err(format!("bundle file {name} takes a layer title the artifact reserves; rename it"));
    }
    addon_lock::verify_files(&lock, &files).map_err(|e| format!("the bundle's files do not match it: {e}"))?;
    let mut layers = Vec::new();
    if let Some((v1_bytes, v1_sig)) = v1 {
        let v1_lock: AddonLock =
            serde_json::from_slice(&v1_bytes).map_err(|e| format!("{LOCK_TITLE} is not an add-on lock: {e}"))?;
        if !v1_sig.trim().starts_with(crate::release_sig::SIG_PREFIX) {
            return Err(format!("{SIG_TITLE} is not a noo-sig1 signature (is it the .sig sign wrote?)"));
        }
        if v1_lock.canonical_bytes() != v1_bytes {
            return Err(format!("{LOCK_TITLE} is not in canonical form; publish the bytes sign wrote"));
        }
        let same = AddonLock { format: addon_lock::FORMAT.to_string(), files: BTreeMap::new(), ..lock.clone() };
        if v1_lock != same {
            return Err(format!(
                "{LOCK_TITLE} ({} {}, format {}) is not the {FORMAT} form of this bundle ({} {}): sign both from the same release",
                v1_lock.addon,
                v1_lock.version,
                v1_lock.format,
                lock.addon,
                lock.version,
                FORMAT = addon_lock::FORMAT
            ));
        }
        layers.push(Blob::new(Some(LOCK_TITLE), LOCK_MEDIA_TYPE, v1_bytes));
        layers.push(Blob::new(Some(SIG_TITLE), SIG_MEDIA_TYPE, v1_sig.into_bytes()));
    }
    layers.push(Blob::new(Some(BUNDLE_TITLE), BUNDLE_MEDIA_TYPE, bundle.clone()));
    layers.push(Blob::new(Some(BUNDLE_SIG_TITLE), SIG_MEDIA_TYPE, bundle_sig.clone().into_bytes()));
    for (name, bytes) in &files {
        layers.push(Blob::new(Some(name.as_str()), FILE_MEDIA_TYPE, bytes.clone()));
    }
    if let Some(big) = layers.iter().find(|l| l.bytes.len() as u64 > MAX_BLOB) {
        return Err(format!(
            "{} is {} bytes; a controller refuses a layer over {MAX_BLOB}",
            big.title.as_deref().unwrap_or_default(),
            big.bytes.len()
        ));
    }
    let config = Blob::new(None, EMPTY_CONFIG_MEDIA_TYPE, EMPTY_CONFIG.to_vec());
    let manifest = manifest_bytes(&config, &layers);
    let manifest_digest = addon_lock::sha256_ref(&manifest);
    Ok(Plan {
        addon: lock.addon.clone(),
        version: lock.version.clone(),
        tags: lock.supports_stack.clone(),
        config,
        layers,
        manifest,
        manifest_digest,
        bundle,
        bundle_sig,
        files,
    })
}

/// The OCI image manifest for `config` and `layers`.
fn manifest_bytes(config: &Blob, layers: &[Blob]) -> Vec<u8> {
    let layers: Vec<serde_json::Value> = layers
        .iter()
        .map(|l| {
            serde_json::json!({"mediaType": l.media_type, "digest": l.digest, "size": l.bytes.len(),
                "annotations": {TITLE_ANNOTATION: l.title.as_deref().unwrap_or_default()}})
        })
        .collect();
    let m = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_ACCEPT,
        "artifactType": ARTIFACT_TYPE,
        "config": {"mediaType": config.media_type, "digest": config.digest, "size": config.bytes.len()},
        "layers": layers,
    });
    // A tree of strings and numbers always serialises.
    serde_json::to_vec(&m).expect("a manifest always serialises")
}

/// `repository:<path>:pull,push`: the scope a push asks for.
pub fn push_scope(path: &str) -> String {
    format!("repository:{path}:pull,push")
}

/// Mask the credential's token, and anything [`release_fetch::redact`]
/// knows, in text that will be shown.
pub fn scrub(text: &str, cred: Option<&Credential>) -> String {
    let mut out = release_fetch::redact(text);
    if let Some(c) = cred {
        let t = c.token.trim();
        if t.len() >= 4 {
            out = out.replace(t, "[redacted]");
        }
    }
    out
}

/// One tag published and read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    pub tag: String,
    pub reference: String,
    /// Blobs uploaded for this publish (the rest were already there); the
    /// count is on the first tag only, since blobs are pushed once.
    pub uploaded: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Head,
    Post,
    Put,
}

impl Method {
    fn name(self) -> &'static str {
        match self {
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
        }
    }
}

/// An OCI registry client that pushes. No redirects are followed, and the
/// Authorization header is never sent to another host.
pub struct Pusher {
    agent: ureq::Agent,
    scheme: &'static str,
    cred: Option<Credential>,
    /// The Authorization header won from the registry's challenge.
    auth: RefCell<Option<String>>,
}

impl Pusher {
    /// The production client: https only, verified by the platform store.
    pub fn new(cred: Option<Credential>) -> Self {
        Pusher { agent: lock_fetch::agent(true, 0), scheme: "https", cred, auth: RefCell::new(None) }
    }

    /// Plain http on loopback, for the fake registry in tests only.
    #[cfg(test)]
    pub(crate) fn plain_http_for_tests(cred: Option<Credential>) -> Self {
        Pusher { agent: lock_fetch::agent(false, 0), scheme: "http", cred, auth: RefCell::new(None) }
    }

    fn send(
        &self,
        m: Method,
        url: &str,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Result<ureq::http::Response<ureq::Body>, FetchError> {
        let auth = self.auth.borrow().clone();
        let r = match m {
            Method::Head => {
                let mut req = self.agent.head(url).header("User-Agent", "noo-cli");
                if let Some(a) = auth.as_deref() {
                    req = req.header("Authorization", a);
                }
                req.call()
            }
            Method::Post | Method::Put => {
                let mut req = if m == Method::Put { self.agent.put(url) } else { self.agent.post(url) };
                req = req.header("User-Agent", "noo-cli");
                if let Some(a) = auth.as_deref() {
                    req = req.header("Authorization", a);
                }
                if let Some(c) = content_type {
                    req = req.header("Content-Type", c);
                }
                req.send(body)
            }
        };
        r.map_err(|e| FetchError::new(release_fetch::classify_transport(&e), format!("{} {url}: {e}", m.name())))
    }

    /// A request with the registry's auth dance: on the first 401, answer its
    /// challenge and retry once.
    fn authed(
        &self,
        m: Method,
        url: &str,
        content_type: Option<&str>,
        body: &[u8],
        host: &str,
        path: &str,
    ) -> Result<ureq::http::Response<ureq::Body>, FetchError> {
        let resp = self.send(m, url, content_type, body)?;
        if resp.status().as_u16() != 401 || self.auth.borrow().is_some() {
            return Ok(resp);
        }
        let challenge = resp
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| FetchError::new(FetchClass::Auth, format!("{} {url} → HTTP 401 with no challenge", m.name())))?;
        let header = self.answer(&challenge, host, path)?;
        *self.auth.borrow_mut() = Some(header);
        self.send(m, url, content_type, body)
    }

    /// The Authorization header that answers `challenge`.
    fn answer(&self, challenge: &str, host: &str, path: &str) -> Result<String, FetchError> {
        let basic = self.cred.as_ref().map(|c| format!("Basic {}", c.basic()));
        let c = challenge.trim();
        if c.get(..6).is_some_and(|p| p.eq_ignore_ascii_case("basic ")) {
            return basic.ok_or_else(|| {
                FetchError::new(FetchClass::Auth, format!("{host} asks for a login, and no credential was given"))
            });
        }
        let params = lock_fetch::parse_bearer_challenge(c)
            .ok_or_else(|| FetchError::new(FetchClass::Auth, format!("unreadable auth challenge from {host}")))?;
        let realm = params.iter().find(|(k, _)| k == "realm").map(|(_, v)| v.clone()).unwrap_or_default();
        let prefix = format!("{}://", self.scheme);
        if !realm.starts_with(&prefix) {
            return Err(FetchError::new(
                FetchClass::Tls,
                format!("the registry's token realm {realm:?} is not {}; refusing to send a credential there", self.scheme),
            ));
        }
        let realm_host = realm[prefix.len()..].split(['/', '?']).next().unwrap_or("");
        if realm_host != host {
            return Err(FetchError::new(
                FetchClass::Auth,
                format!("the registry's token realm {realm:?} is not on the registry host {host}; refusing to send a credential there"),
            ));
        }
        let mut query: Vec<String> =
            params.iter().filter(|(k, _)| k == "service").map(|(k, v)| format!("{k}={}", lock_fetch::pct(v))).collect();
        query.push(format!("scope={}", lock_fetch::pct(&push_scope(path))));
        let sep = if realm.contains('?') { '&' } else { '?' };
        let url = format!("{realm}{sep}{}", query.join("&"));
        let mut req = self.agent.get(&url).header("User-Agent", "noo-cli");
        if let Some(b) = basic.as_deref() {
            req = req.header("Authorization", b);
        }
        let resp = req
            .call()
            .map_err(|e| FetchError::new(release_fetch::classify_transport(&e), format!("token request to {realm_host}: {e}")))?;
        let status = resp.status().as_u16();
        if let Some((class, _)) = release_fetch::classify_status(status, &|_| None, 0) {
            let why = lock_fetch::read_capped(resp, MAX_BLOB, "token response").ok().and_then(|b| lock_fetch::registry_error_message(&b));
            let who = if self.cred.is_some() { "the credential" } else { "an anonymous request (no credential given)" };
            return Err(FetchError::new(class, match why {
                Some(m) => format!("token request for {} → HTTP {status} for {who}: {m}", push_scope(path)),
                None => format!("token request for {} → HTTP {status} for {who}", push_scope(path)),
            }));
        }
        let body = lock_fetch::read_capped(resp, MAX_BLOB, "token response")?;
        let v: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| FetchError::new(FetchClass::Other, format!("token response is not JSON: {e}")))?;
        v.get("token")
            .or_else(|| v.get("access_token"))
            .and_then(|t| t.as_str())
            .filter(|t| !t.is_empty())
            .map(|t| format!("Bearer {t}"))
            .ok_or_else(|| FetchError::new(FetchClass::Auth, "token response carries no token"))
    }

    /// The registry's refusal of `what`: its status and its error message.
    fn refusal(what: &str, resp: ureq::http::Response<ureq::Body>) -> FetchError {
        let status = resp.status().as_u16();
        let class = release_fetch::classify_status(status, &|_| None, 0).map(|c| c.0).unwrap_or(FetchClass::Other);
        let why = lock_fetch::read_capped(resp, MAX_BLOB, what).ok().and_then(|b| lock_fetch::registry_error_message(&b));
        FetchError::new(class, match why {
            Some(m) => format!("{what} → HTTP {status}: {m}"),
            None => format!("{what} → HTTP {status}"),
        })
    }

    /// Push one blob unless the registry has it. True when it was uploaded.
    fn push_blob(&self, host: &str, path: &str, b: &Blob) -> Result<bool, FetchError> {
        let base = format!("{}://{host}/v2/{path}", self.scheme);
        let what = b.title.as_deref().unwrap_or("config");
        let resp = self.authed(Method::Head, &format!("{base}/blobs/{}", b.digest), None, &[], host, path)?;
        let status = resp.status().as_u16();
        match status {
            // A redirect is the registry pointing at the blob's storage: it has it.
            200 | 300..=399 => return Ok(false),
            404 => {}
            _ => return Err(Self::refusal(&format!("HEAD blob {} ({what})", b.digest), resp)),
        }
        let resp = self.authed(Method::Post, &format!("{base}/blobs/uploads/"), None, &[], host, path)?;
        if !(200..300).contains(&resp.status().as_u16()) {
            return Err(Self::refusal(&format!("starting the upload of {what}"), resp));
        }
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| FetchError::new(FetchClass::Other, format!("the registry started the upload of {what} with no Location")))?;
        let url = upload_url(self.scheme, host, &location, &b.digest).map_err(|e| FetchError::new(FetchClass::Other, e))?;
        let resp = self.authed(Method::Put, &url, Some("application/octet-stream"), &b.bytes, host, path)?;
        if !(200..300).contains(&resp.status().as_u16()) {
            return Err(Self::refusal(&format!("uploading {what} ({})", b.digest), resp));
        }
        Ok(true)
    }

    /// Push `manifest` under `tag`.
    fn push_manifest(&self, host: &str, path: &str, tag: &str, manifest: &[u8]) -> Result<(), FetchError> {
        let url = format!("{}://{host}/v2/{path}/manifests/{tag}", self.scheme);
        let resp = self.authed(Method::Put, &url, Some(MANIFEST_ACCEPT), manifest, host, path)?;
        if !(200..300).contains(&resp.status().as_u16()) {
            return Err(Self::refusal(&format!("PUT manifest {tag}"), resp));
        }
        Ok(())
    }
}

/// The URL the upload's bytes go to: the registry's `Location` (relative to
/// the registry, or absolute on the same scheme and host) with
/// `digest=<digest>` added. A Location on another host is refused: the
/// registry's Authorization would follow it there.
pub fn upload_url(scheme: &str, host: &str, location: &str, digest: &str) -> Result<String, String> {
    let loc = location.trim();
    let full = if loc.starts_with('/') {
        format!("{scheme}://{host}{loc}")
    } else if let Some(rest) = loc.strip_prefix(&format!("{scheme}://")) {
        let loc_host = rest.split(['/', '?']).next().unwrap_or("");
        if loc_host != host {
            return Err(format!("the registry sent the upload to {loc_host}, not {host}; refusing to send a credential there"));
        }
        loc.to_string()
    } else {
        return Err(format!("the registry's upload Location {loc:?} is not on {scheme}://{host}"));
    };
    let sep = if full.contains('?') { '&' } else { '?' };
    Ok(format!("{full}{sep}digest={}", lock_fetch::pct(digest)))
}

/// Push `plan` to `root` under every tag, then read each tag back through
/// `fetcher` (the upgrade's own fetch) and require the bytes pushed. The
/// error names the artifact (`<root>:stack-<tag>`) it failed on.
pub fn publish(pusher: &Pusher, fetcher: &lock_fetch::Client, root: &str, plan: &Plan) -> Result<Vec<Published>, String> {
    let scrubbed = |e: String| scrub(&e, pusher.cred.as_ref());
    let (host, path) = lock_fetch::split_root(root).ok_or_else(|| format!("registry root {root:?} is not host/path"))?;
    let mut uploaded = 0;
    for b in std::iter::once(&plan.config).chain(plan.layers.iter()) {
        let up = pusher
            .push_blob(host, path, b)
            .map_err(|e| scrubbed(format!("{root}: {}", e.summary())))?;
        uploaded += usize::from(up);
    }
    let route = lock_fetch::Route::Direct { root: root.to_string() };
    let mut out = Vec::new();
    for tag in &plan.tags {
        let reference = lock_fetch::artifact_ref(root, tag);
        pusher
            .push_manifest(host, path, &lock_fetch::lock_tag(tag), &plan.manifest)
            .map_err(|e| scrubbed(format!("{reference}: {}", e.summary())))?;
        let got = fetcher
            .fetch_via(&route, tag)
            .map_err(|e| scrubbed(format!("{reference} was pushed and does not read back: {}", e.summary())))?;
        read_back_matches(plan, &got).map_err(|e| scrubbed(format!("{reference} was pushed and reads back wrong: {e}")))?;
        let first = out.is_empty();
        out.push(Published { tag: tag.clone(), reference, uploaded: if first { uploaded } else { 0 } });
    }
    Ok(out)
}

/// The read-back holds exactly the bundle, its signature and its files.
fn read_back_matches(plan: &Plan, got: &lock_fetch::Fetched) -> Result<(), String> {
    if got.lock != plan.bundle {
        return Err(format!(
            "the registry serves a lock hashing to {}, and {} was pushed",
            addon_lock::sha256_ref(&got.lock),
            addon_lock::sha256_ref(&plan.bundle)
        ));
    }
    if got.sig != plan.bundle_sig {
        return Err(format!("the registry serves another {BUNDLE_SIG_TITLE} than was pushed"));
    }
    if got.files != plan.files {
        let names = |m: &BTreeMap<String, Vec<u8>>| m.keys().cloned().collect::<Vec<_>>().join(", ");
        return Err(format!("the registry serves files [{}], and [{}] were pushed", names(&got.files), names(&plan.files)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::addons::lock_fetch::fake::{self, Seen, Server};

    const PATH: &str = "example/intel";
    /// The fake's credential: a made-up user and token, nothing real.
    const USER: &str = "dev";
    const TOKEN: &str = "fake-push-token-0001";
    const BEARER: &str = "fake-bearer";
    const OVERLAY: &[u8] = b"services:\n  example-addon:\n    image: x\n";

    /// What the fake registry holds: blobs by digest, manifests by tag.
    #[derive(Default)]
    struct State {
        blobs: BTreeMap<String, Vec<u8>>,
        manifests: BTreeMap<String, Vec<u8>>,
        uploads: usize,
    }

    #[derive(Clone, Default)]
    struct Opts {
        /// Every /v2/ request needs `Bearer <BEARER>`, which the realm hands
        /// out for Basic `USER:TOKEN`.
        gated: bool,
        /// The upload Location is absolute (else relative).
        absolute_location: bool,
        /// Serve this as the bundle lock on a read-back (a registry that
        /// accepts the push and serves something else).
        swap_lock: Option<Vec<u8>>,
    }

    fn reg_error(status: u16, msg: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
        (status, vec![], serde_json::json!({"errors": [{"code": "X", "message": msg}]}).to_string().into_bytes())
    }

    /// A push-capable OCI registry on loopback (HEAD/GET/POST/PUT on blobs
    /// and manifests), over the shared fake's transport.
    fn registry(opts: Opts, state: Arc<Mutex<State>>) -> Server {
        fake::serve_fn(move |base| {
            let base = base.to_string();
            let uploads = format!("/v2/{PATH}/blobs/uploads/");
            let blobs = format!("/v2/{PATH}/blobs/");
            let manifests = format!("/v2/{PATH}/manifests/");
            move |req: &Seen| {
                let (key, query) = req.path.split_once('?').unwrap_or((req.path.as_str(), ""));
                if key == "/token" {
                    let want = format!("Basic {}", fake::basic(USER, TOKEN));
                    if req.auth.as_deref() == Some(want.as_str()) {
                        return (200, vec![], serde_json::json!({"token": BEARER}).to_string().into_bytes());
                    }
                    return reg_error(401, "bad credentials");
                }
                let bearer = format!("Bearer {BEARER}");
                if opts.gated && req.auth.as_deref() != Some(bearer.as_str()) {
                    let ch = format!("Bearer realm=\"{base}/token\",service=\"reg\",scope=\"repository:{PATH}:pull\"");
                    return (401, vec![("WWW-Authenticate".to_string(), ch)], vec![]);
                }
                let mut st = state.lock().unwrap();
                match req.method.as_str() {
                    "POST" if key == uploads => {
                        st.uploads += 1;
                        let loc = format!("{uploads}u{}", st.uploads);
                        let loc = if opts.absolute_location { format!("{base}{loc}") } else { loc };
                        (202, vec![("Location".to_string(), loc)], vec![])
                    }
                    "PUT" if key.starts_with(&uploads) => {
                        let d = query.split('&').find_map(|kv| kv.strip_prefix("digest=")).unwrap_or("").replace("%3A", ":");
                        if addon_lock::sha256_ref(&req.body) != d {
                            return reg_error(400, "digest does not match the bytes");
                        }
                        st.blobs.insert(d, req.body.clone());
                        (201, vec![], vec![])
                    }
                    "HEAD" if key.starts_with(&blobs) => {
                        let found = st.blobs.contains_key(&key[blobs.len()..]);
                        (if found { 200 } else { 404 }, vec![], vec![])
                    }
                    "GET" if key.starts_with(&blobs) => match st.blobs.get(&key[blobs.len()..]) {
                        Some(b) => (200, vec![], b.clone()),
                        None => reg_error(404, "blob unknown"),
                    },
                    "PUT" if key.starts_with(&manifests) => {
                        st.manifests.insert(key[manifests.len()..].to_string(), req.body.clone());
                        (201, vec![], vec![])
                    }
                    "GET" if key.starts_with(&manifests) => {
                        let Some(m) = st.manifests.get(&key[manifests.len()..]).cloned() else {
                            return reg_error(404, "manifest unknown");
                        };
                        let Some(other) = opts.swap_lock.clone() else { return (200, vec![], m) };
                        let mut v: serde_json::Value = serde_json::from_slice(&m).unwrap();
                        for l in v["layers"].as_array_mut().unwrap() {
                            if l["annotations"][TITLE_ANNOTATION] == BUNDLE_TITLE {
                                l["digest"] = addon_lock::sha256_ref(&other).into();
                                l["size"] = other.len().into();
                            }
                        }
                        st.blobs.insert(addon_lock::sha256_ref(&other), other);
                        (200, vec![], serde_json::to_vec(&v).unwrap())
                    }
                    _ => reg_error(404, "unknown"),
                }
            }
        })
    }

    fn root(s: &Server) -> String {
        format!("{}/{PATH}", s.base.trim_start_matches("http://"))
    }

    fn cred(token: &str) -> Credential {
        Credential { user: USER.into(), token: token.into() }
    }

    fn lock_for(root: &str, format: &str, files: BTreeMap<String, String>) -> AddonLock {
        AddonLock {
            format: format.into(),
            addon: "example_addon".into(),
            version: "1.2.0".into(),
            source_commit: "0123456789abcdef0123456789abcdef01234567".into(),
            supports_stack: vec!["v0.6.23".into(), "v0.6.24".into()],
            images: BTreeMap::from([("example-addon".to_string(), format!("{root}/example-addon@sha256:{}", "a".repeat(64)))]),
            base: None,
            files,
        }
    }

    /// A release as `sign` writes it: the bundle (with the overlay), the v1
    /// pair, each signature with its trailing newline.
    fn inputs(root: &str) -> Inputs {
        let seed = "ab".repeat(32);
        let files = BTreeMap::from([(addon_lock::OVERLAY_FILE.to_string(), OVERLAY.to_vec())]);
        let listed = files.iter().map(|(k, v)| (k.clone(), addon_lock::sha256_ref(v))).collect();
        let (bundle, bsig) = addon_lock::sign(&lock_for(root, addon_lock::FORMAT_V2, listed), &seed).unwrap();
        let (v1, v1sig) = addon_lock::sign(&lock_for(root, addon_lock::FORMAT, BTreeMap::new()), &seed).unwrap();
        Inputs { bundle, bundle_sig: format!("{bsig}\n"), v1: Some((v1, format!("{v1sig}\n"))), files }
    }

    fn run(opts: Opts, state: Arc<Mutex<State>>, push: Option<Credential>, read: Option<Credential>) -> (Server, Plan, Result<Vec<Published>, String>) {
        let reg = registry(opts, state);
        let r = root(&reg);
        let plan = plan(inputs(&r), &r).expect("plan");
        let bound = read.map(|cred| lock_fetch::Bound { addon: plan.addon.clone(), root: r.clone(), cred });
        let fetcher = lock_fetch::Client::plain_http_for_tests(None).with_bound(bound);
        let out = publish(&Pusher::plain_http_for_tests(push), &fetcher, &r, &plan);
        (reg, plan, out)
    }

    #[test]
    fn a_publish_reads_back_through_lock_fetch_for_every_supported_tag() {
        let state = Arc::new(Mutex::new(State::default()));
        let (reg, plan, out) = run(Opts::default(), state, None, None);
        let out = out.expect("publish");
        assert_eq!(out.iter().map(|p| p.tag.as_str()).collect::<Vec<_>>(), ["v0.6.23", "v0.6.24"]);
        assert!(out[0].reference.ends_with(":stack-v0.6.23"), "{out:?}");
        for tag in ["v0.6.23", "v0.6.24"] {
            let f = lock_fetch::Client::plain_http_for_tests(None).fetch(&root(&reg), tag).expect("the upgrade's fetch reads it");
            assert_eq!(f.lock, plan.bundle, "{tag}: the lock bytes pushed");
            assert_eq!(f.sig, plan.bundle_sig, "{tag}");
            assert_eq!(f.files.get(addon_lock::OVERLAY_FILE).map(Vec::as_slice), Some(OVERLAY), "{tag}");
        }
    }

    #[test]
    fn the_pushed_manifest_carries_the_artifact_type_and_the_titled_layers_lock_fetch_needs() {
        let state = Arc::new(Mutex::new(State::default()));
        let (reg, plan, out) = run(Opts::default(), state.clone(), None, None);
        out.expect("publish");
        let st = state.lock().unwrap();
        assert_eq!(st.manifests.keys().map(String::as_str).collect::<Vec<_>>(), ["stack-v0.6.23", "stack-v0.6.24"]);
        for m in st.manifests.values() {
            assert_eq!(m, &plan.manifest, "one manifest, pushed under every tag");
        }
        let v: serde_json::Value = serde_json::from_slice(&st.manifests["stack-v0.6.24"]).unwrap();
        assert_eq!(v["schemaVersion"], 2);
        assert_eq!(v["mediaType"], MANIFEST_ACCEPT);
        assert_eq!(v["artifactType"], ARTIFACT_TYPE);
        assert_eq!(v["config"]["mediaType"], EMPTY_CONFIG_MEDIA_TYPE);
        assert_eq!(v["config"]["digest"], addon_lock::sha256_ref(EMPTY_CONFIG));
        assert_eq!(st.blobs.get(&addon_lock::sha256_ref(EMPTY_CONFIG)).map(Vec::as_slice), Some(EMPTY_CONFIG), "the config blob is pushed");
        let layers: Vec<(String, String)> = v["layers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| (l["annotations"][TITLE_ANNOTATION].as_str().unwrap().to_string(), l["mediaType"].as_str().unwrap().to_string()))
            .collect();
        let want: Vec<(String, String)> = [
            (LOCK_TITLE, LOCK_MEDIA_TYPE),
            (SIG_TITLE, SIG_MEDIA_TYPE),
            (BUNDLE_TITLE, BUNDLE_MEDIA_TYPE),
            (BUNDLE_SIG_TITLE, SIG_MEDIA_TYPE),
            (addon_lock::OVERLAY_FILE, FILE_MEDIA_TYPE),
        ]
        .iter()
        .map(|(t, m)| (t.to_string(), m.to_string()))
        .collect();
        assert_eq!(layers, want, "the oras recipe's layers, in its order");
        for l in v["layers"].as_array().unwrap() {
            let d = l["digest"].as_str().unwrap();
            assert_eq!(st.blobs.get(d).map(Vec::len), l["size"].as_u64().map(|s| s as usize), "{d} pushed at its size");
        }
        let seen = reg.seen.lock().unwrap().clone();
        let puts: Vec<&Seen> = seen.iter().filter(|s| s.method == "PUT" && s.path.contains("/manifests/")).collect();
        assert_eq!(puts.len(), 2, "{seen:?}");
        assert!(puts.iter().all(|s| s.header("content-type") == Some(MANIFEST_ACCEPT)), "{puts:?}");
    }

    #[test]
    fn a_blob_the_registry_already_has_is_not_uploaded_again() {
        let state = Arc::new(Mutex::new(State::default()));
        {
            let mut st = state.lock().unwrap();
            st.blobs.insert(addon_lock::sha256_ref(EMPTY_CONFIG), EMPTY_CONFIG.to_vec());
            st.blobs.insert(addon_lock::sha256_ref(OVERLAY), OVERLAY.to_vec());
        }
        let (reg, plan, out) = run(Opts::default(), state.clone(), None, None);
        let out = out.expect("publish");
        assert_eq!(plan.layers.len() + 1, 6, "config and five layers");
        assert_eq!(out[0].uploaded, 4, "{out:?}");
        assert_eq!(state.lock().unwrap().uploads, 4, "one upload per absent blob");
        let seen = reg.seen.lock().unwrap().clone();
        let overlay = lock_fetch::pct(&addon_lock::sha256_ref(OVERLAY));
        assert!(seen.iter().any(|s| s.method == "HEAD" && s.path.ends_with(&addon_lock::sha256_ref(OVERLAY))), "{seen:?}");
        assert!(!seen.iter().any(|s| s.method == "PUT" && s.path.contains(&overlay)), "the overlay was uploaded again: {seen:?}");
    }

    #[test]
    fn a_bearer_challenge_is_answered_with_basic_at_the_realm_and_the_token_is_never_shown() {
        let state = Arc::new(Mutex::new(State::default()));
        let opts = Opts { gated: true, ..Opts::default() };
        let (reg, _, out) = run(opts.clone(), state, Some(cred(TOKEN)), Some(cred(TOKEN)));
        let out = out.expect("publish behind a token");
        assert!(!format!("{out:?}").contains(TOKEN));
        let seen = reg.seen.lock().unwrap().clone();
        assert!(seen[0].auth.is_none(), "the first request is anonymous: {:?}", seen[0]);
        let basic = format!("Basic {}", fake::basic(USER, TOKEN));
        let push_token = seen
            .iter()
            .find(|s| s.path.starts_with("/token?") && s.path.contains("scope=repository%3Aexample%2Fintel%3Apull%2Cpush"))
            .unwrap_or_else(|| panic!("no push-scoped token request: {seen:?}"));
        assert_eq!(push_token.auth.as_deref(), Some(basic.as_str()), "Basic user:token to the realm");
        assert!(push_token.path.contains("service=reg"), "{push_token:?}");
        let bearer = format!("Bearer {BEARER}");
        assert!(
            seen.iter().filter(|s| s.method == "PUT").all(|s| s.auth.as_deref() == Some(bearer.as_str())),
            "every upload carries the Bearer token: {seen:?}"
        );
        assert!(seen.iter().filter(|s| !s.path.starts_with("/token")).all(|s| s.auth.as_deref() != Some(basic.as_str())), "Basic only to the realm");

        // A token the realm refuses: the push fails, and says so without it.
        let wrong = "fake-wrong-token-0002";
        let (_, _, out) = run(opts, Arc::new(Mutex::new(State::default())), Some(cred(wrong)), Some(cred(wrong)));
        let e = out.expect_err("refused");
        assert!(e.contains("access refused") && e.contains("HTTP 401"), "{e}");
        assert!(!e.contains(wrong) && !e.contains(TOKEN), "{e}");
    }

    #[test]
    fn a_registry_that_serves_another_lock_back_fails_the_publish_naming_the_tag() {
        let state = Arc::new(Mutex::new(State::default()));
        let opts = Opts { swap_lock: Some(b"another lock".to_vec()), ..Opts::default() };
        let (_, _, out) = run(opts, state, None, None);
        let e = out.expect_err("verify-on-publish refuses it");
        assert!(e.contains(":stack-v0.6.23") && e.contains("reads back wrong"), "{e}");
        assert!(e.contains(&addon_lock::sha256_ref(b"another lock")), "{e}");
    }

    #[test]
    fn a_tag_that_does_not_read_back_fails_the_publish_naming_it() {
        // The registry takes the manifest and then has nothing under the tag.
        let reg = fake::serve_fn(|_| {
            |req: &Seen| match req.method.as_str() {
                "HEAD" => (200, vec![], vec![]),
                "PUT" => (201, vec![], vec![]),
                _ => reg_error(404, "manifest unknown"),
            }
        });
        let r = root(&reg);
        let plan = plan(inputs(&r), &r).unwrap();
        let e = publish(&Pusher::plain_http_for_tests(None), &lock_fetch::Client::plain_http_for_tests(None), &r, &plan).unwrap_err();
        assert!(e.contains(":stack-v0.6.23 was pushed and does not read back") && e.contains("not found"), "{e}");
    }

    #[test]
    fn an_absolute_upload_location_on_the_registry_is_followed() {
        let state = Arc::new(Mutex::new(State::default()));
        let (_, _, out) = run(Opts { absolute_location: true, ..Opts::default() }, state, None, None);
        out.expect("publish");
    }

    #[test]
    fn upload_urls() {
        let d = format!("sha256:{}", "a".repeat(64));
        let q = format!("digest=sha256%3A{}", "a".repeat(64));
        assert_eq!(upload_url("https", "reg.example", "/v2/p/blobs/uploads/u1", &d).unwrap(), format!("https://reg.example/v2/p/blobs/uploads/u1?{q}"));
        assert_eq!(upload_url("https", "reg.example", "https://reg.example/v2/p/u?_state=x", &d).unwrap(), format!("https://reg.example/v2/p/u?_state=x&{q}"));
        assert!(upload_url("https", "reg.example", "https://storage.example/u", &d).unwrap_err().contains("refusing to send a credential"));
        assert!(upload_url("https", "reg.example", "http://reg.example/u", &d).is_err(), "a scheme downgrade");
        assert!(upload_url("https", "reg.example", "u1", &d).is_err());
    }

    #[test]
    fn a_publish_refuses_what_no_controller_would_read() {
        let r = "ghcr.io/example/intel";
        let ok = inputs(r);
        assert_eq!(plan(ok.clone(), r).unwrap().layers.len(), 5);
        // Bundle-only: the bundle pair and its files.
        let p = plan(Inputs { v1: None, ..ok.clone() }, r).unwrap();
        assert_eq!(p.layers.iter().map(|l| l.title.clone().unwrap()).collect::<Vec<_>>(), [BUNDLE_TITLE, BUNDLE_SIG_TITLE, addon_lock::OVERLAY_FILE]);
        // The v1 lock handed in as the bundle.
        let (v1, v1s) = ok.v1.clone().unwrap();
        let e = plan(Inputs { bundle: v1, bundle_sig: v1s, ..ok.clone() }, r).unwrap_err();
        assert!(e.contains(addon_lock::FORMAT_V2) && e.contains("--file"), "{e}");
        // Re-serialised bytes.
        let pretty = serde_json::to_vec_pretty(&serde_json::from_slice::<serde_json::Value>(&ok.bundle).unwrap()).unwrap();
        assert!(plan(Inputs { bundle: pretty, ..ok.clone() }, r).unwrap_err().contains("canonical"));
        // Images outside the root.
        assert!(plan(ok.clone(), "ghcr.io/other/pkg").unwrap_err().contains("would be refused"));
        // A file edited after signing, and a file missing.
        let edited = BTreeMap::from([(addon_lock::OVERLAY_FILE.to_string(), b"edited".to_vec())]);
        assert!(plan(Inputs { files: edited, ..ok.clone() }, r).unwrap_err().contains(addon_lock::OVERLAY_FILE));
        assert!(plan(Inputs { files: BTreeMap::new(), ..ok.clone() }, r).unwrap_err().contains("is missing"));
        // A v1 lock from another release.
        let seed = "ab".repeat(32);
        let mut other = lock_for(r, addon_lock::FORMAT, BTreeMap::new());
        other.version = "1.1.0".into();
        let (b, s) = addon_lock::sign(&other, &seed).unwrap();
        let e = plan(Inputs { v1: Some((b, s)), ..ok.clone() }, r).unwrap_err();
        assert!(e.contains("1.1.0") && e.contains("same release"), "{e}");
        // Not a signature.
        assert!(plan(Inputs { bundle_sig: "garbage".into(), ..ok }, r).unwrap_err().contains("noo-sig1"));
    }

    #[test]
    fn scrub_masks_the_token() {
        let c = cred("fake-push-token-0001");
        assert_eq!(scrub("a fake-push-token-0001 b", Some(&c)), "a [redacted] b");
        assert_eq!(scrub("nothing here", None), "nothing here");
    }
}
