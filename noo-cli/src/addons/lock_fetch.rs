// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Fetch an add-on's signed lock from its own registry package.
//!
//! An add-on release publishes its lock as an OCI artifact in the same
//! package as its image, tagged `stack-<stack tag>`: one manifest of
//! artifactType [`ARTIFACT_TYPE`] with two layers, the lock
//! ([`LOCK_TITLE`]) and its `noo-sig1` signature ([`SIG_TITLE`]). The
//! package is the add-on's registry root, which the entitlement names
//! (`addons.<name>.registry`). So one `read:packages` credential reads both
//! the lock and the images, and that credential cannot read source. The
//! layout is documented in docs/development/addons.md; the add-on release
//! workflows publish exactly this.
//!
//! The flow is the OCI distribution API:
//!   1. `GET /v2/<path>/manifests/stack-<tag>`. A 401 carries a Bearer
//!      challenge; the token comes from its realm, with Basic
//!      `<user>:<NOO_ADDON_REGISTRY_TOKEN>` when the store holds one.
//!   2. The manifest must name [`ARTIFACT_TYPE`] and both titled layers with
//!      their media types.
//!   3. Each blob is fetched by digest, capped at [`MAX_BLOB`], and its
//!      sha256 is checked against the manifest before it is used.
//!
//! The BUNDLE (N6). The same manifest may also carry the bundle lock
//! ([`BUNDLE_TITLE`], format `noo-addon-lock/2`, which lists `files`), its
//! signature ([`BUNDLE_SIG_TITLE`]) and one [`FILE_MEDIA_TYPE`] layer per
//! listed file, titled with the file name. A CLI from before the bundle reads
//! only the two v1 layers and ignores the rest, so a release publishes both
//! forms in one artifact. When the bundle layers are present this client
//! takes the bundle and its files and leaves the v1 pair alone; without them
//! it takes the v1 pair and no files (the caller decides what a bundle-less
//! add-on may do).
//!
//! TLS is always on: the agent is https-only with the platform verifier, so
//! a realm or a redirect that leaves https fails loud. The Authorization
//! header is never carried across a redirect (`RedirectAuthHeaders::Never`):
//! GHCR answers a blob with a redirect to a storage host that must not see
//! the registry token. Nothing here believes the bytes: the caller passes
//! them to [`crate::addon_lock::verify`] against the entitlement's anchor.

use std::io::Read as _;
use std::time::Duration;

use sha2::Digest as _;

use crate::release_fetch::{self, FetchClass, FetchError};

/// The manifest's `artifactType`.
pub const ARTIFACT_TYPE: &str = "application/vnd.noomesh.addon-lock.v1";
/// The lock layer's media type.
pub const LOCK_MEDIA_TYPE: &str = "application/vnd.noomesh.addon-lock.v1+json";
/// The signature layer's media type.
pub const SIG_MEDIA_TYPE: &str = "application/vnd.noomesh.addon-lock.sig.v1";
/// The layer titles (`org.opencontainers.image.title`), which are the file
/// names `noo security addon-lock sign --out addon-lock.json` writes.
pub const LOCK_TITLE: &str = "addon-lock.json";
pub const SIG_TITLE: &str = "addon-lock.json.sig";
/// The bundle lock layer (format `noo-addon-lock/2`) and its signature.
pub const BUNDLE_TITLE: &str = "addon-bundle.json";
pub const BUNDLE_SIG_TITLE: &str = "addon-bundle.json.sig";
pub const BUNDLE_MEDIA_TYPE: &str = "application/vnd.noomesh.addon-bundle.v1+json";
/// One file the bundle lock lists, titled with its file name.
pub const FILE_MEDIA_TYPE: &str = "application/vnd.noomesh.addon-file.v1";
/// No add-on ships more files than this beside its images.
pub const MAX_FILES: usize = 32;
const TITLE_ANNOTATION: &str = "org.opencontainers.image.title";
const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json";
/// No lock or signature is anywhere near this; a larger blob is refused
/// before it is read.
pub const MAX_BLOB: u64 = 1 << 20;

/// The store key holding the controller's registry credential: a token that
/// can read the add-on packages (`read:packages` on GHCR). Read from the
/// encrypted store only, never from `.env`.
pub const TOKEN_KEY: &str = "NOO_ADDON_REGISTRY_TOKEN";
/// The user name sent with it. Optional; GHCR checks only the token.
pub const USER_KEY: &str = "NOO_ADDON_REGISTRY_USER";
const DEFAULT_USER: &str = "noo";

/// The tag an add-on lock for `stack_tag` is published under.
pub fn lock_tag(stack_tag: &str) -> String {
    format!("stack-{}", stack_tag.trim())
}

/// `<root>:stack-<tag>`, for messages.
pub fn artifact_ref(root: &str, stack_tag: &str) -> String {
    format!("{}:{}", root.trim(), lock_tag(stack_tag))
}

/// `ghcr.io/owner/pkg` → (`ghcr.io`, `owner/pkg`).
pub fn split_root(root: &str) -> Option<(&str, &str)> {
    let (host, path) = root.trim().split_once('/')?;
    (!host.is_empty() && !path.is_empty()).then_some((host, path))
}

/// The registry credential. `Debug` never prints the token.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    pub user: String,
    pub token: String,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Credential {{ user: {:?}, token: <redacted> }}", self.user)
    }
}

impl Credential {
    fn basic(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", self.user, self.token))
    }
}

/// The credential installed on this controller. Its only home is the
/// encrypted store: never `.env`. `Ok(None)` = no token stored (fetches then
/// go anonymous and a private package answers "access refused"); `Err` = the
/// store could not be read, which is never "no token".
pub fn installed_credential() -> Result<Option<Credential>, String> {
    let root = crate::envfile::repo_root();
    if !crate::envfile::sops_backend_active() {
        return Ok(None);
    }
    let path = root.join("secrets/env.sops");
    let store = crate::commands::secrets::SecretStore::load_sops(&path)
        .map_err(|e| format!("{} could not be read for {TOKEN_KEY}: {e}", path.display()))?;
    let get = |k: &str| store.get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let Some(token) = get(TOKEN_KEY) else { return Ok(None) };
    // The user name is not a secret, so it may sit in `.env` beside it.
    let env_user = crate::onboard::env::read_env_key(&root.join(".env"), USER_KEY).trim().to_string();
    let user = get(USER_KEY)
        .or((!env_user.is_empty()).then_some(env_user))
        .unwrap_or_else(|| DEFAULT_USER.to_string());
    Ok(Some(Credential { user, token }))
}

/// The lock and signature as fetched, before any verification. From a
/// bundle, `lock` is the bundle lock and `files` its files by name (each
/// blob already checked against the manifest digest, and nothing else yet:
/// `addon_lock::verify_files` holds them to the signed lock). From a
/// v1-only artifact, `files` is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub lock: Vec<u8>,
    pub sig: String,
    pub files: std::collections::BTreeMap<String, Vec<u8>>,
}

/// An OCI registry client for add-on locks.
pub struct Client {
    /// Manifest and token requests: no redirects at all.
    agent: ureq::Agent,
    /// Blob requests: redirects allowed (GHCR answers with one), never with
    /// the Authorization header.
    blob_agent: ureq::Agent,
    scheme: &'static str,
    cred: Option<Credential>,
    /// The registry host of the current fetch: the token realm must be on it.
    host: std::cell::RefCell<String>,
}

impl Client {
    /// The production client: https only, verified by the platform trust
    /// store, Authorization never forwarded on a redirect.
    pub fn new(cred: Option<Credential>) -> Self {
        Client { agent: agent(true, 0), blob_agent: agent(true, 5), scheme: "https", cred, host: Default::default() }
    }

    /// Plain http on loopback, for the fake registry in tests only.
    #[cfg(test)]
    pub(crate) fn plain_http_for_tests(cred: Option<Credential>) -> Self {
        Client { agent: agent(false, 0), blob_agent: agent(false, 5), scheme: "http", cred, host: Default::default() }
    }

    fn get(&self, url: &str, accept: Option<&str>, auth: Option<&str>) -> Result<ureq::http::Response<ureq::Body>, FetchError> {
        self.get_via(&self.agent, url, accept, auth)
    }

    /// GET through `agent`: the caller picks it by what it fetches (manifest
    /// and token: no redirects; blob: redirects without Authorization).
    fn get_via(
        &self,
        agent: &ureq::Agent,
        url: &str,
        accept: Option<&str>,
        auth: Option<&str>,
    ) -> Result<ureq::http::Response<ureq::Body>, FetchError> {
        let mut req = agent.get(url).header("User-Agent", "noo-cli");
        if let Some(a) = accept {
            req = req.header("Accept", a);
        }
        if let Some(a) = auth {
            req = req.header("Authorization", a);
        }
        req.call().map_err(|e| FetchError::new(release_fetch::classify_transport(&e), format!("GET {url}: {e}")))
    }

    /// GET with the registry's token dance: an anonymous first request,
    /// then one retry with a Bearer token from the challenge's realm.
    fn get_authed(
        &self,
        agent: &ureq::Agent,
        url: &str,
        accept: Option<&str>,
        bearer: &mut Option<String>,
    ) -> Result<ureq::http::Response<ureq::Body>, FetchError> {
        let auth = bearer.as_ref().map(|t| format!("Bearer {t}"));
        let resp = self.get_via(agent, url, accept, auth.as_deref())?;
        if resp.status().as_u16() != 401 || bearer.is_some() {
            return Ok(resp);
        }
        let challenge = resp
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| FetchError::new(FetchClass::Auth, format!("GET {url} → HTTP 401 with no token challenge")))?;
        let token = self.token(&challenge)?;
        *bearer = Some(token);
        let auth = bearer.as_ref().map(|t| format!("Bearer {t}"));
        self.get_via(agent, url, accept, auth.as_deref())
    }

    /// Exchange the credential for a Bearer token at the challenge's realm.
    fn token(&self, challenge: &str) -> Result<String, FetchError> {
        let params = parse_bearer_challenge(challenge)
            .ok_or_else(|| FetchError::new(FetchClass::Auth, format!("unreadable token challenge {challenge:?}")))?;
        let realm = params.iter().find(|(k, _)| k == "realm").map(|(_, v)| v.clone()).unwrap_or_default();
        if !realm.starts_with(&format!("{}://", self.scheme)) {
            return Err(FetchError::new(
                FetchClass::Tls,
                format!("the registry's token realm {realm:?} is not {}; refusing to send a credential there", self.scheme),
            ));
        }
        let realm_host = realm[self.scheme.len() + 3..].split(['/', '?']).next().unwrap_or("");
        if realm_host != self.host.borrow().as_str() {
            return Err(FetchError::new(
                FetchClass::Auth,
                format!("the registry's token realm {realm:?} is not on the registry host {}; refusing to send a credential there",
                    self.host.borrow()),
            ));
        }
        let query: Vec<String> = params
            .iter()
            .filter(|(k, _)| k == "service" || k == "scope")
            .map(|(k, v)| format!("{k}={}", pct(v)))
            .collect();
        let url = if query.is_empty() { realm } else { format!("{realm}?{}", query.join("&")) };
        let basic = self.cred.as_ref().map(|c| format!("Basic {}", c.basic()));
        let resp = self.get(&url, None, basic.as_deref())?;
        let status = resp.status().as_u16();
        if let Some((class, _)) = release_fetch::classify_status(status, &|_| None, 0) {
            return Err(FetchError::new(class, format!("token request → HTTP {status}")));
        }
        let body = read_capped(resp, MAX_BLOB, "token response")?;
        let v: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| FetchError::new(FetchClass::Other, format!("token response is not JSON: {e}")))?;
        v.get("token")
            .or_else(|| v.get("access_token"))
            .and_then(|t| t.as_str())
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .ok_or_else(|| FetchError::new(FetchClass::Auth, "token response carries no token"))
    }

    /// Fetch the lock artifact `<root>:stack-<stack_tag>`.
    pub fn fetch(&self, root: &str, stack_tag: &str) -> Result<Fetched, FetchError> {
        let Some((host, path)) = split_root(root) else {
            return Err(FetchError::new(FetchClass::Other, format!("registry root {root:?} is not host/path")));
        };
        *self.host.borrow_mut() = host.to_string();
        let base = format!("{}://{host}/v2/{path}", self.scheme);
        let mut bearer: Option<String> = None;
        let url = format!("{base}/manifests/{}", lock_tag(stack_tag));
        let resp = self.get_authed(&self.agent, &url, Some(MANIFEST_ACCEPT), &mut bearer)?;
        let status = resp.status().as_u16();
        if let Some((class, _)) = release_fetch::classify_status(status, &|_| None, 0) {
            return Err(FetchError::new(class, format!("{} → HTTP {status}", artifact_ref(root, stack_tag))));
        }
        let manifest = read_capped(resp, MAX_BLOB, "manifest")?;
        let layers = parse_manifest(&manifest).map_err(|e| {
            FetchError::new(FetchClass::Other, format!("{}: {e}", artifact_ref(root, stack_tag)))
        })?;
        let mut blob = |l: &Layer| -> Result<Vec<u8>, FetchError> {
            let url = format!("{base}/blobs/{}", l.digest);
            let resp = self.get_authed(&self.blob_agent, &url, None, &mut bearer)?;
            let status = resp.status().as_u16();
            if let Some((class, _)) = release_fetch::classify_status(status, &|_| None, 0) {
                return Err(FetchError::new(class, format!("blob {} ({}) → HTTP {status}", l.digest, l.title)));
            }
            let bytes = read_capped(resp, MAX_BLOB, &l.title)?;
            let got = format!("sha256:{}", hex(&sha2::Sha256::digest(&bytes)));
            if got != l.digest {
                return Err(FetchError::new(
                    FetchClass::Other,
                    format!("{} does not match its digest: the manifest says {}, the bytes hash to {got}", l.title, l.digest),
                ));
            }
            Ok(bytes)
        };
        let lock = blob(&layers.lock)?;
        let sig = blob(&layers.sig)?;
        let sig = String::from_utf8(sig)
            .map_err(|_| FetchError::new(FetchClass::Other, format!("{} is not text", layers.sig.title)))?;
        let mut files = std::collections::BTreeMap::new();
        for l in &layers.files {
            files.insert(l.title.clone(), blob(l)?);
        }
        Ok(Fetched { lock, sig, files })
    }
}

fn agent(https_only: bool, max_redirects: u32) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(60)))
        .http_status_as_error(false)
        .https_only(https_only)
        .max_redirects(max_redirects)
        .redirect_auth_headers(ureq::config::RedirectAuthHeaders::Never)
        .build()
        .into()
}

fn read_capped(resp: ureq::http::Response<ureq::Body>, cap: u64, what: &str) -> Result<Vec<u8>, FetchError> {
    let mut buf = Vec::new();
    resp.into_body()
        .into_reader()
        .take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|e| FetchError::new(FetchClass::Network, format!("{what}: body cut off: {e}")))?;
    if buf.len() as u64 > cap {
        return Err(FetchError::new(FetchClass::Other, format!("{what} is larger than {cap} bytes; refused")));
    }
    Ok(buf)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Percent-encode a query value (scope strings carry `:` and `/`).
fn pct(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// `Bearer realm="…",service="…",scope="…"` → its parameters, in order.
pub(crate) fn parse_bearer_challenge(h: &str) -> Option<Vec<(String, String)>> {
    let rest = h.trim().strip_prefix("Bearer ").or_else(|| h.trim().strip_prefix("bearer "))?;
    let mut out = Vec::new();
    let mut s = rest.trim();
    while !s.is_empty() {
        let (k, after) = s.split_once('=')?;
        let k = k.trim().trim_start_matches(',').trim().to_ascii_lowercase();
        let after = after.trim_start();
        let (v, tail) = if let Some(q) = after.strip_prefix('"') {
            let end = q.find('"')?;
            (q[..end].to_string(), &q[end + 1..])
        } else {
            let end = after.find(',').unwrap_or(after.len());
            (after[..end].trim().to_string(), &after[end..])
        };
        out.push((k, v));
        s = tail.trim_start().trim_start_matches(',').trim_start();
    }
    Some(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Layer {
    title: String,
    digest: String,
}

/// The layers this client fetches: the bundle pair and its files when the
/// manifest carries a bundle, else the v1 pair.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Layers {
    lock: Layer,
    sig: Layer,
    files: Vec<Layer>,
}

/// The manifest's layers to fetch, or why it is not an add-on lock.
fn parse_manifest(bytes: &[u8]) -> Result<Layers, String> {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| format!("manifest is not JSON: {e}"))?;
    let at = v.get("artifactType").and_then(|a| a.as_str()).unwrap_or("");
    if at != ARTIFACT_TYPE {
        return Err(format!("artifactType is {at:?}, not {ARTIFACT_TYPE}"));
    }
    let layers = v.get("layers").and_then(|l| l.as_array()).ok_or("manifest has no layers")?;
    let title_of = |l: &serde_json::Value| -> Option<String> {
        l.pointer(&format!("/annotations/{}", TITLE_ANNOTATION.replace('/', "~1"))).and_then(|t| t.as_str()).map(str::to_string)
    };
    let check = |l: &serde_json::Value, title: &str, media: &str| -> Result<Layer, String> {
        let mt = l.get("mediaType").and_then(|m| m.as_str()).unwrap_or("");
        if mt != media {
            return Err(format!("layer {title} has mediaType {mt:?}, not {media}"));
        }
        let digest = l.get("digest").and_then(|d| d.as_str()).unwrap_or("").to_string();
        if !crate::addon_lock::is_sha256_digest(&digest) {
            return Err(format!("layer {title} digest {digest:?} is not sha256:<64 hex>"));
        }
        if l.get("size").and_then(|s| s.as_u64()).is_some_and(|s| s > MAX_BLOB) {
            return Err(format!("layer {title} is larger than {MAX_BLOB} bytes"));
        }
        Ok(Layer { title: title.to_string(), digest })
    };
    // Zero or one layer per title; `required` makes zero an error.
    let find = |title: &str, media: &str, required: bool| -> Result<Option<Layer>, String> {
        let hits: Vec<&serde_json::Value> = layers.iter().filter(|l| title_of(l).as_deref() == Some(title)).collect();
        match hits.as_slice() {
            [] if !required => Ok(None),
            [l] => check(l, title, media).map(Some),
            _ => Err(format!("manifest needs exactly one layer titled {title}, found {}", hits.len())),
        }
    };
    let bundle = find(BUNDLE_TITLE, BUNDLE_MEDIA_TYPE, false)?;
    let bundle_sig = find(BUNDLE_SIG_TITLE, SIG_MEDIA_TYPE, false)?;
    let mut files = Vec::new();
    for l in layers.iter().filter(|l| l.get("mediaType").and_then(|m| m.as_str()) == Some(FILE_MEDIA_TYPE)) {
        let title = title_of(l).unwrap_or_default();
        if !crate::addon_lock::valid_file_name(&title) {
            return Err(format!("bundle file layer title {title:?} is not a plain file name"));
        }
        if files.iter().any(|f: &Layer| f.title == title) {
            return Err(format!("manifest has two bundle file layers titled {title}"));
        }
        files.push(check(l, &title, FILE_MEDIA_TYPE)?);
    }
    if files.len() > MAX_FILES {
        return Err(format!("manifest carries {} bundle files; at most {MAX_FILES} are read", files.len()));
    }
    match (bundle, bundle_sig) {
        (Some(lock), Some(sig)) => Ok(Layers { lock, sig, files }),
        (None, None) if files.is_empty() => {
            let lock = find(LOCK_TITLE, LOCK_MEDIA_TYPE, true)?.expect("required");
            let sig = find(SIG_TITLE, SIG_MEDIA_TYPE, true)?.expect("required");
            Ok(Layers { lock, sig, files })
        }
        (None, None) => Err(format!("manifest carries bundle files and no {BUNDLE_TITLE}")),
        (Some(_), None) => Err(format!("manifest has {BUNDLE_TITLE} and no {BUNDLE_SIG_TITLE}")),
        (None, Some(_)) => Err(format!("manifest has {BUNDLE_SIG_TITLE} and no {BUNDLE_TITLE}")),
    }
}

/// The manifest of a bundle release: the v1 pair, the bundle pair and one
/// layer per file, as the fake registry in tests serves it.
#[cfg(test)]
pub(crate) fn bundle_manifest_for(v1: (&[u8], &[u8]), bundle: (&[u8], &[u8]), files: &[(&str, &[u8])]) -> String {
    let d = |b: &[u8]| format!("sha256:{}", hex(&sha2::Sha256::digest(b)));
    let mut m: serde_json::Value = serde_json::from_str(&manifest_for(v1.0, v1.1)).unwrap();
    let layers = m["layers"].as_array_mut().unwrap();
    for (media, title, b) in [(BUNDLE_MEDIA_TYPE, BUNDLE_TITLE, bundle.0), (SIG_MEDIA_TYPE, BUNDLE_SIG_TITLE, bundle.1)]
        .into_iter()
        .chain(files.iter().map(|(n, b)| (FILE_MEDIA_TYPE, *n, *b)))
    {
        layers.push(serde_json::json!({"mediaType": media, "digest": d(b), "size": b.len(),
            "annotations": {TITLE_ANNOTATION: title}}));
    }
    m.to_string()
}

/// The OCI manifest an add-on release publishes for `lock` and `sig`, as the
/// fake registry in tests serves it (and as the docs show it).
#[cfg(test)]
pub(crate) fn manifest_for(lock: &[u8], sig: &[u8]) -> String {
    let d = |b: &[u8]| format!("sha256:{}", hex(&sha2::Sha256::digest(b)));
    serde_json::json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_ACCEPT,
        "artifactType": ARTIFACT_TYPE,
        "config": {"mediaType": "application/vnd.oci.empty.v1+json",
                   "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "size": 2},
        "layers": [
            {"mediaType": LOCK_MEDIA_TYPE, "digest": d(lock), "size": lock.len(),
             "annotations": {TITLE_ANNOTATION: LOCK_TITLE}},
            {"mediaType": SIG_MEDIA_TYPE, "digest": d(sig), "size": sig.len(),
             "annotations": {TITLE_ANNOTATION: SIG_TITLE}},
        ]
    })
    .to_string()
}

#[cfg(test)]
pub(crate) mod fake {
    //! A scripted OCI registry on loopback. It records every request line
    //! and its Authorization header, so tests assert what crossed the wire.
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Debug)]
    pub struct Seen {
        pub path: String,
        pub auth: Option<String>,
    }

    /// path → (status, headers, body). `{base}` in a header value is
    /// replaced with the server's own base URL.
    pub type Routes = BTreeMap<String, (u16, Vec<(String, String)>, Vec<u8>)>;

    pub struct Server {
        pub base: String,
        pub seen: Arc<Mutex<Vec<Seen>>>,
    }

    pub fn serve(routes: impl FnOnce(&str) -> Routes) -> Server {
        serve_gated(routes, None)
    }

    /// Like [`serve`], but every `/v2/` request without `Authorization:
    /// Bearer <token>` is answered 401 with a challenge whose realm is this
    /// server's `/token` (which the routes must answer).
    pub fn serve_gated(routes: impl FnOnce(&str) -> Routes, bearer: Option<&'static str>) -> Server {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let routes = routes(&base);
        let realm = format!("{base}/token");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        std::thread::spawn(move || {
            for stream in l.incoming() {
                let Ok(mut st) = stream else { continue };
                let mut rd = BufReader::new(st.try_clone().unwrap());
                let mut first = String::new();
                let _ = rd.read_line(&mut first);
                let mut auth = None;
                loop {
                    let mut line = String::new();
                    if rd.read_line(&mut line).is_err() || line.trim().is_empty() {
                        break;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("authorization") {
                            auth = Some(v.trim().to_string());
                        }
                    }
                }
                let path = first.split_whitespace().nth(1).unwrap_or("").to_string();
                s2.lock().unwrap().push(Seen { path: path.clone(), auth: auth.clone() });
                let key = path.split('?').next().unwrap_or("").to_string();
                let gated = bearer.is_some_and(|t| key.starts_with("/v2/") && auth.as_deref() != Some(&format!("Bearer {t}")));
                let (status, hdrs, body) = if gated {
                    let ch = format!("Bearer realm=\"{realm}\",service=\"reg\",scope=\"repository:example/intel:pull\"");
                    (401, vec![("WWW-Authenticate".to_string(), ch)], Vec::new())
                } else {
                    routes.get(&key).cloned().unwrap_or((404, vec![], b"{\"errors\":[{\"code\":\"NOT_FOUND\"}]}".to_vec()))
                };
                let mut resp = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
                for (k, v) in hdrs {
                    resp.push_str(&format!("{k}: {v}\r\n"));
                }
                resp.push_str("\r\n");
                let _ = st.write_all(resp.as_bytes());
                let _ = st.write_all(&body);
            }
        });
        Server { base, seen }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{serve, serve_gated, Routes};
    use super::*;

    const ROOT_PATH: &str = "example/intel";

    fn root(base: &str) -> String {
        format!("{}/{ROOT_PATH}", base.trim_start_matches("http://"))
    }

    fn blob_path(b: &[u8]) -> String {
        format!("/v2/{ROOT_PATH}/blobs/sha256:{}", hex(&sha2::Sha256::digest(b)))
    }

    /// A registry that wants a Bearer token, serves the artifact for v0.6.0,
    /// and answers each blob with a redirect to a second host (as GHCR does).
    fn registry(lock: &'static [u8], sig: &'static [u8], storage: &str) -> super::fake::Server {
        let storage = storage.to_string();
        serve_gated(
            move |_| {
                let mut r = Routes::new();
                r.insert(
                    format!("/v2/{ROOT_PATH}/manifests/stack-v0.6.0"),
                    (200, vec![("Content-Type".into(), MANIFEST_ACCEPT.into())], manifest_for(lock, sig).into_bytes()),
                );
                r.insert("/token".into(), (200, vec![], br#"{"token":"T0K"}"#.to_vec()));
                for b in [lock, sig] {
                    let p = blob_path(b);
                    r.insert(p.clone(), (307, vec![("Location".into(), format!("{storage}{p}"))], vec![]));
                }
                r
            },
            Some("T0K"),
        )
    }

    fn storage(lock: &'static [u8], sig: &'static [u8]) -> super::fake::Server {
        serve(move |_| {
            let mut r = Routes::new();
            for b in [lock, sig] {
                r.insert(blob_path(b), (200, vec![], b.to_vec()));
            }
            r
        })
    }

    #[test]
    fn token_dance_then_both_layers_and_no_auth_across_the_blob_redirect() {
        let (lock, sig): (&'static [u8], &'static [u8]) = (b"{\"lock\":1}", b"noo-sig1 x\n");
        let st = storage(lock, sig);
        let reg = registry(lock, sig, &st.base);
        let cred = Credential { user: "bot".into(), token: "s3cret".into() };
        let c = Client::plain_http_for_tests(Some(cred.clone()));
        let f = c.fetch(&root(&reg.base), "v0.6.0").expect("fetch");
        assert_eq!(f.lock, lock);
        assert_eq!(f.sig, "noo-sig1 x\n");

        let seen = reg.seen.lock().unwrap().clone();
        assert!(seen[0].auth.is_none(), "the first request is anonymous: {seen:?}");
        assert!(seen[1].path.starts_with("/token?service=reg&scope=repository%3Aexample%2Fintel%3Apull"), "{:?}", seen[1]);
        assert_eq!(seen[1].auth.as_deref(), Some(format!("Basic {}", cred.basic()).as_str()), "Basic to the realm only");
        assert!(seen[2..].iter().all(|s| s.auth.as_deref() == Some("Bearer T0K")), "{seen:?}");
        assert_eq!(seen.iter().filter(|s| s.path.starts_with("/token")).count(), 1, "one token for the whole fetch");

        let stored = st.seen.lock().unwrap().clone();
        assert_eq!(stored.len(), 2, "{stored:?}");
        assert!(stored.iter().all(|s| s.auth.is_none()), "a registry credential crossed the redirect: {stored:?}");
    }

    #[test]
    fn a_token_the_registry_still_refuses_is_access_refused_and_never_echoed() {
        let reg = serve_gated(
            |_| {
                let mut r = Routes::new();
                r.insert("/token".into(), (200, vec![], br#"{"token":"WRONG"}"#.to_vec()));
                r
            },
            Some("T0K"),
        );
        let c = Client::plain_http_for_tests(Some(Credential { user: "bot".into(), token: "s3cret".into() }));
        let e = c.fetch(&root(&reg.base), "v0.6.0").expect_err("still 401 after the token");
        assert_eq!(e.class, FetchClass::Auth, "{e}");
        assert!(!e.to_string().contains("s3cret") && !e.to_string().contains("WRONG"), "{e}");
    }

    #[test]
    fn a_token_endpoint_that_refuses_the_credential_is_access_refused() {
        let reg = serve_gated(
            |_| {
                let mut r = Routes::new();
                r.insert("/token".into(), (403, vec![], b"denied".to_vec()));
                r
            },
            Some("T0K"),
        );
        let e = Client::plain_http_for_tests(None).fetch(&root(&reg.base), "v0.6.0").unwrap_err();
        assert_eq!(e.class, FetchClass::Auth, "{e}");
    }

    #[test]
    fn a_missing_tag_is_not_found() {
        let reg = serve(|_| Routes::new());
        let e = Client::plain_http_for_tests(None).fetch(&root(&reg.base), "v9.9.9").unwrap_err();
        assert_eq!(e.class, FetchClass::NotFound, "{e}");
        assert!(e.detail.contains("stack-v9.9.9"), "{e}");
    }

    #[test]
    fn a_blob_whose_bytes_do_not_match_its_digest_is_refused() {
        let (lock, sig): (&'static [u8], &'static [u8]) = (b"L", b"S");
        let reg = serve(|_| {
            let mut r = Routes::new();
            r.insert(format!("/v2/{ROOT_PATH}/manifests/stack-v0.6.0"), (200, vec![], manifest_for(lock, sig).into_bytes()));
            r.insert(blob_path(lock), (200, vec![], b"tampered".to_vec()));
            r.insert(blob_path(sig), (200, vec![], sig.to_vec()));
            r
        });
        let e = Client::plain_http_for_tests(None).fetch(&root(&reg.base), "v0.6.0").unwrap_err();
        assert!(e.detail.contains("does not match its digest"), "{e}");
    }

    #[test]
    fn a_bundle_artifact_yields_the_bundle_lock_and_its_files_and_skips_the_v1_pair() {
        let (v1, v1s): (&'static [u8], &'static [u8]) = (b"V1", b"V1SIG");
        let (b, bs): (&'static [u8], &'static [u8]) = (b"BUNDLE", b"BSIG");
        let overlay: &'static [u8] = b"services: {}\n";
        let reg = serve(move |_| {
            let mut r = Routes::new();
            r.insert(
                format!("/v2/{ROOT_PATH}/manifests/stack-v0.6.0"),
                (200, vec![], bundle_manifest_for((v1, v1s), (b, bs), &[("docker-compose.yml", overlay)]).into_bytes()),
            );
            for x in [b, bs, overlay] {
                r.insert(blob_path(x), (200, vec![], x.to_vec()));
            }
            r
        });
        let f = Client::plain_http_for_tests(None).fetch(&root(&reg.base), "v0.6.0").expect("fetch");
        assert_eq!(f.lock, b);
        assert_eq!(f.sig, "BSIG");
        assert_eq!(f.files.len(), 1);
        assert_eq!(f.files["docker-compose.yml"], overlay);
        let seen = reg.seen.lock().unwrap().clone();
        assert!(!seen.iter().any(|s| s.path == blob_path(v1)), "the v1 lock was fetched beside the bundle: {seen:?}");

        // A v1-only artifact: the v1 pair and no files, as before.
        let reg = serve(move |_| {
            let mut r = Routes::new();
            r.insert(format!("/v2/{ROOT_PATH}/manifests/stack-v0.6.0"), (200, vec![], manifest_for(v1, v1s).into_bytes()));
            for x in [v1, v1s] {
                r.insert(blob_path(x), (200, vec![], x.to_vec()));
            }
            r
        });
        let f = Client::plain_http_for_tests(None).fetch(&root(&reg.base), "v0.6.0").expect("fetch");
        assert_eq!((f.lock.as_slice(), f.sig.as_str(), f.files.len()), (v1, "V1SIG", 0));
    }

    #[test]
    fn bundle_manifest_rules() {
        let ok = bundle_manifest_for((b"L", b"S"), (b"B", b"BS"), &[("docker-compose.yml", b"x")]);
        let l = parse_manifest(ok.as_bytes()).unwrap();
        assert_eq!((l.lock.title.as_str(), l.sig.title.as_str(), l.files.len()), (BUNDLE_TITLE, BUNDLE_SIG_TITLE, 1));
        let no_bundle_sig = ok.replace(BUNDLE_SIG_TITLE, "other");
        assert!(parse_manifest(no_bundle_sig.as_bytes()).unwrap_err().contains(BUNDLE_SIG_TITLE));
        let a_path = bundle_manifest_for((b"L", b"S"), (b"B", b"BS"), &[("../x", b"x")]);
        assert!(parse_manifest(a_path.as_bytes()).unwrap_err().contains("plain file name"));
        let twice = bundle_manifest_for((b"L", b"S"), (b"B", b"BS"), &[("a.yml", b"x"), ("a.yml", b"y")]);
        assert!(parse_manifest(twice.as_bytes()).unwrap_err().contains("two bundle file layers"));
        // Files with no bundle lock to list them are refused, not ignored.
        let mut m: serde_json::Value = serde_json::from_str(&ok).unwrap();
        m["layers"].as_array_mut().unwrap().retain(|l| {
            let t = l["annotations"][TITLE_ANNOTATION].as_str().unwrap_or("");
            t != BUNDLE_TITLE && t != BUNDLE_SIG_TITLE
        });
        assert!(parse_manifest(m.to_string().as_bytes()).unwrap_err().contains("no addon-bundle.json"));
        // A bundle-only artifact (no v1 pair) is enough for this client.
        let mut m: serde_json::Value = serde_json::from_str(&ok).unwrap();
        m["layers"].as_array_mut().unwrap().retain(|l| {
            let t = l["annotations"][TITLE_ANNOTATION].as_str().unwrap_or("");
            t != LOCK_TITLE && t != SIG_TITLE
        });
        assert!(parse_manifest(m.to_string().as_bytes()).is_ok());
    }

    #[test]
    fn manifest_rules() {
        let ok = manifest_for(b"L", b"S");
        assert!(parse_manifest(ok.as_bytes()).is_ok());
        let wrong_type = ok.replace(ARTIFACT_TYPE, "application/vnd.example");
        assert!(parse_manifest(wrong_type.as_bytes()).unwrap_err().contains("artifactType"));
        let wrong_media = ok.replace(SIG_MEDIA_TYPE, "text/plain");
        assert!(parse_manifest(wrong_media.as_bytes()).unwrap_err().contains("mediaType"));
        let no_sig = ok.replace(SIG_TITLE, "other.sig");
        assert!(parse_manifest(no_sig.as_bytes()).unwrap_err().contains(SIG_TITLE));
        assert!(parse_manifest(b"[]").is_err());
    }

    #[test]
    fn production_client_is_https_only_and_refuses_a_plain_or_foreign_realm() {
        let c = Client::new(Some(Credential { user: "u".into(), token: "t".into() }));
        assert_eq!(c.scheme, "https");
        *c.host.borrow_mut() = "ghcr.io".into();
        let e = c.token("Bearer realm=\"http://evil.example/token\",service=\"x\"").unwrap_err();
        assert_eq!(e.class, FetchClass::Tls, "{e}");
        assert!(e.detail.contains("refusing to send a credential"), "{e}");
        let e = c.token("Bearer realm=\"https://evil.example/token\",service=\"x\"").unwrap_err();
        assert!(e.detail.contains("not on the registry host ghcr.io"), "{e}");
        // An http URL — what a downgrade redirect would hand it — is refused
        // by the agent itself, before any byte is sent.
        let st = serve(|_| Routes::new());
        let e = c.get_via(&c.blob_agent, &format!("{}/blobs/x", st.base), None, None).unwrap_err();
        assert_eq!(e.class, FetchClass::Tls, "{e}");
        assert!(st.seen.lock().unwrap().is_empty(), "a plain-http request reached the server");
    }

    #[test]
    fn manifest_requests_do_not_follow_redirects() {
        let reg = serve(|base| {
            let mut r = Routes::new();
            r.insert(format!("/v2/{ROOT_PATH}/manifests/stack-v0.6.0"), (307, vec![("Location".into(), format!("{base}/elsewhere"))], vec![]));
            r
        });
        let e = Client::plain_http_for_tests(None).fetch(&root(&reg.base), "v0.6.0").unwrap_err();
        assert!(reg.seen.lock().unwrap().iter().all(|s| s.path != "/elsewhere"), "the redirect was followed");
        // Not followed, and not taken for a manifest: a refusal of its own.
        assert_eq!(e.class, FetchClass::Other, "{e}");
        assert!(e.detail.contains("HTTP 307") || e.detail.contains("redirect"), "{e}");
    }

    #[test]
    fn challenge_parsing() {
        let p = parse_bearer_challenge("Bearer realm=\"https://ghcr.io/token\",service=\"ghcr.io\",scope=\"repository:a/b:pull\"").unwrap();
        assert_eq!(p[0], ("realm".into(), "https://ghcr.io/token".into()));
        assert_eq!(p[2], ("scope".into(), "repository:a/b:pull".into()));
        assert!(parse_bearer_challenge("Basic realm=\"x\"").is_none());
    }

    #[test]
    fn credential_debug_hides_the_token() {
        let c = Credential { user: "u".into(), token: "s3cret".into() };
        assert!(!format!("{c:?}").contains("s3cret"));
    }

    #[test]
    fn refs_and_roots() {
        assert_eq!(artifact_ref("ghcr.io/o/p", "v0.6.0"), "ghcr.io/o/p:stack-v0.6.0");
        assert_eq!(split_root("ghcr.io/o/p"), Some(("ghcr.io", "o/p")));
        assert_eq!(split_root("ghcr.io"), None);
    }
}
