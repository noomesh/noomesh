// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC
//! Signed console entry paths. Only the shell runs on the console origin.
use crate::{addon_proxy::AddonManifest, state::AppState};
use axum::{
    extract::OriginalUri,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, OnceLock},
};

static MOUNTED: OnceLock<BTreeMap<String, Vec<String>>> = OnceLock::new();
static MOUNT_REFUSED: OnceLock<BTreeMap<String, String>> = OnceLock::new();

fn claims(manifests: &[AddonManifest]) -> BTreeMap<String, Vec<String>> {
    let mut paths: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for m in manifests {
        if let Some(path) = m.ui.as_ref().and_then(|ui| ui.console_path.as_ref()) {
            paths.entry(path.clone()).or_default().push(m.addon.clone());
        }
    }
    for owners in paths.values_mut() {
        owners.sort();
        owners.dedup();
    }
    paths
}

fn collision(path: &str, owners: &[String]) -> String {
    format!("console path {path:?} is claimed by {}; change one signed ui.console_path and restart the gateway", owners.join(", "))
}

/// Mount once at startup; every request checks the current registry again.
/// Duplicate claims mount only a conflict response, never either add-on.
pub fn mount(mut router: Router<Arc<AppState>>) -> Router<Arc<AppState>> {
    let paths = claims(&crate::addon_proxy::manifests());
    let mut refused = BTreeMap::new();
    let mut installed = BTreeMap::new();
    for (path, owners) in &paths {
        let candidate = router.clone();
        let route = path.clone();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            candidate.route(&route, get(serve))
        })) {
            Ok(next) => {
                router = next;
                installed.insert(path.clone(), owners.clone());
            }
            Err(_) => {
                for owner in owners {
                    refused.insert(owner.clone(), format!("console path {path:?} overlaps a core route; change the signed ui.console_path"));
                }
            }
        }
    }
    let _ = MOUNTED.set(installed);
    let _ = MOUNT_REFUSED.set(refused);
    for (addon, why) in refusals() {
        tracing::error!(%addon, %why, "add-on console path refused");
    }
    router
}

/// Old mounted paths remain public *shell* endpoints so a disabled or changed
/// claim returns 404, including for a signed-out bookmark. No data is exposed.
pub fn is_claimed_console_path(path: &str) -> bool {
    MOUNTED.get().is_some_and(|paths| paths.contains_key(path))
}

pub fn refusals() -> BTreeMap<String, String> {
    let mut out = MOUNT_REFUSED.get().cloned().unwrap_or_default();
    for (path, owners) in claims(&crate::addon_proxy::manifests()) {
        if owners.len() > 1 {
            let why = collision(&path, &owners);
            for owner in owners {
                out.insert(owner, why.clone());
            }
        }
    }
    out
}

pub fn listed_path(addon: &str, path: Option<&str>) -> Option<String> {
    let path = path?;
    if refusals().contains_key(addon) {
        return None;
    }
    MOUNTED
        .get()?
        .get(path)?
        .iter()
        .any(|owner| owner == addon)
        .then(|| path.to_string())
}

fn live_owner<'a>(
    paths: &'a BTreeMap<String, Vec<String>>,
    path: &str,
    enabled: &dyn Fn(&str) -> bool,
) -> Result<&'a str, (StatusCode, String)> {
    let owners = paths
        .get(path)
        .ok_or((StatusCode::NOT_FOUND, String::new()))?;
    if owners.len() != 1 {
        return Err((StatusCode::CONFLICT, collision(path, owners)));
    }
    let _ = enabled; // TEST MUTANT: ignore disabled state.
    Ok(&owners[0])
}

async fn serve(OriginalUri(uri): OriginalUri, headers: HeaderMap) -> Response {
    let manifests = crate::addon_proxy::manifests();
    let paths = claims(&manifests);
    let owner = match live_owner(&paths, uri.path(), &|name| {
        crate::addons::enabled(name) && crate::addon_registry::get(name).is_some()
    }) {
        Ok(owner) => owner,
        Err((code, detail)) => {
            return (code, [("cache-control", "no-store")], detail).into_response()
        }
    };
    if refusals().contains_key(owner) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(m) = manifests.iter().find(|m| m.addon == owner) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let ui = m.ui.as_ref().expect("claim came from a UI");
    let origin = crate::addon_ui::embedding_origin(&headers, owner);
    let mut response = crate::routes::ui::serve_index_with_addon(Some(owner)).await;
    let configured = std::env::var("NOO_CSP").ok();
    response.headers_mut().extend(shell_headers(
        origin.as_deref(),
        ui.frame_permissions.as_deref().unwrap_or_default(),
        configured.as_deref(),
    ));
    response
}

pub(crate) fn shell_headers(
    origin: Option<&str>,
    permissions: &[addon_manifest::FramePermission],
    configured: Option<&str>,
) -> HeaderMap {
    use addon_manifest::FramePermission as P;
    use axum::http::{HeaderName, HeaderValue};
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    let policy = [
        P::Microphone,
        P::Camera,
        P::Autoplay,
        P::Fullscreen,
        P::ClipboardWrite,
    ]
    .into_iter()
    .map(
        |permission| match origin.filter(|_| permissions.contains(&permission)) {
            Some(origin) => format!("{}=(self \"{origin}\")", permission.as_str()),
            None => format!("{}=()", permission.as_str()),
        },
    )
    .chain(std::iter::once("geolocation=()".into()))
    .collect::<Vec<_>>()
    .join(", ");
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_str(&policy).unwrap(),
    );
    // Chromium requires the embedding document to retain each delegated
    // capability as well; without self it denies the child microphone.
    if let Some(origin) = origin {
        if crate::middleware::csp_choice(configured) == crate::middleware::CspChoice::Default {
            headers.insert(
                HeaderName::from_static("content-security-policy"),
                HeaderValue::from_str(&format!(
                    "{}; frame-src {origin}",
                    crate::middleware::DEFAULT_CSP
                ))
                .unwrap(),
            );
        }
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_duplicate_claimants_are_reported_deterministically() {
        let make = |addon: &str| {
            serde_json::from_value(serde_json::json!({"version":1,"addon":addon,"base_url_env":"NOO_RHADDON_URL","base_url_default":"https://noo-rhaddon:9000","routes":[],"ui":{"console_path":"/shared-space"}})).unwrap()
        };
        let paths = claims(&[make("zaddon"), make("aaddon")]);
        assert_eq!(paths["/shared-space"], vec!["aaddon", "zaddon"]);
        assert!(collision("/shared-space", &paths["/shared-space"]).contains("aaddon, zaddon"));
    }
    #[test]
    fn disabled_changed_and_duplicate_paths_fail_closed() {
        let mut paths = BTreeMap::from([("/example-space".into(), vec!["rhaddon".into()])]);
        assert_eq!(
            live_owner(&paths, "/example-space", &|_| true).unwrap(),
            "rhaddon"
        );
        assert_eq!(
            live_owner(&paths, "/example-space", &|_| false)
                .unwrap_err()
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            live_owner(&paths, "/old-space", &|_| true).unwrap_err().0,
            StatusCode::NOT_FOUND
        );
        paths
            .get_mut("/example-space")
            .unwrap()
            .push("other-addon".into());
        assert_eq!(
            live_owner(&paths, "/example-space", &|_| true)
                .unwrap_err()
                .0,
            StatusCode::CONFLICT
        );
    }
    #[test]
    fn real_core_router_rejects_overlap_and_accepts_unclaimed_space() {
        // Actual core router, including static services, without infrastructure
        // or AppState. Axum's registration conflict is the production backstop.
        for path in ["/dashboard", "/health", "/kiosk"] {
            assert!(
                addon_manifest::CONSOLE_RESERVED_SEGMENTS.contains(&path.trim_start_matches('/'))
            );
            let core = crate::routes::core_router();
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || core.route(path, get(|| async { "probe" }))
            ))
            .is_err());
        }
        let core = crate::routes::core_router();
        let probe_path = "/example-space";
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || core.route(probe_path, get(|| async { "probe" }))
        ))
        .is_ok());
    }
    #[test]
    fn delegates_only_signed_capabilities_to_the_exact_origin() {
        let permissions = [
            addon_manifest::FramePermission::Microphone,
            addon_manifest::FramePermission::Autoplay,
        ];
        let h = shell_headers(Some("https://mesh.test:8458"), &permissions, None);
        assert_eq!(h["permissions-policy"], "microphone=(self \"https://mesh.test:8458\"), camera=(), autoplay=(self \"https://mesh.test:8458\"), fullscreen=(), clipboard-write=(), geolocation=()");
        assert!(h["content-security-policy"]
            .to_str()
            .unwrap()
            .ends_with("frame-src https://mesh.test:8458"));
        for custom in ["off", "default-src 'none'"] {
            assert!(
                !shell_headers(Some("https://mesh.test:8458"), &permissions, Some(custom))
                    .contains_key("content-security-policy")
            );
        }
        assert!(
            shell_headers(None, &permissions, None)["permissions-policy"]
                .to_str()
                .unwrap()
                .contains("microphone=()")
        );
    }
}
