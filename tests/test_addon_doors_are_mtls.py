# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every HTTP add-on door is HTTPS with a required cluster-CA client cert.

an earlier change. The gateway's add-on proxy (`gateway-rust/src/addon_proxy.rs`)
sends the gateway's own bearer (`Authorization: Bearer …`, the
`addon-caller:gateway` key) and the requester identity headers on every call.
Until 1256 evolve's route manifest said
`"base_url_default": "http://noo-evolve:8090"` and evolve's uvicorn bound
`0.0.0.0:8090` in plain HTTP — the bearer crossed `noo-cluster`/`noo-db` in
the clear, and anything on those networks could call a route. Every other
in-cluster door (vLLM, the stunnel sidecars, Postgres, Redis, NATS, Loki,
Alertmanager, model-cache) already required a client certificate.

What this pins, from the shipped files:

  1. the gateway refuses a route manifest that does not dial
     `https://noo-<addon>` (manifests ship with the add-on now and are
     validated at startup, `addon_proxy::validate`; the Rust unit test
     `every_addon_door_is_https` plants `http://`);
  2. every such add-on has a row in LISTENER_TLS below (a new HTTP add-on
     without one fails, naming it). That its service declares the row's
     cert / key / client-CA env under its own `services/<addon>` leaf and
     the cluster CA is pinned in the add-on's repo, beside its overlay (N6:
     the licensed overlays left core);
  3. the leaf's SANs (onboard `svc_extra_hostnames`) cover the host the
     manifest dials, so the gateway's verification can succeed at all;
  4. (no healthcheck dialling plain `http://`: pinned in the add-on's repo, N6);
  5. the proxy dials through `crate::tls::cluster_client()` (presents the
     gateway leaf, verifies against the cluster CA) and refuses a
     non-`https://` base URL before sending;
  6. when an evolve add-on checkout is named (`NOO_EVOLVE_PATH`), its server
     hands uvicorn `ssl.CERT_REQUIRED` and its dev overlay declares the same
     three variables. the add-on's own `tests/test_serve_tls.py` pins the
     server from that side with a real listener; this is the cross-check.

The listener-side check is necessarily per add-on (the env names are the
add-on's), which is why it is a table and why a manifest without a row fails
rather than being skipped. The HTTP add-ons are the `routes_manifest: true`
rows of `addons::ADDONS`, and the host each is dialled at is `noo-<addon>`,
the only upstream `addon_proxy::validate` accepts.

Planted 2026-09-29: `https://` → `http://` in evolve's manifest →
the gateway's manifest check failed naming evolve. Restored from `.bak`.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlparse

import pytest


ROOT = Path(__file__).resolve().parents[1]
ADDONS_RS = ROOT / "gateway-rust" / "src" / "addons.rs"
PROXY = ROOT / "gateway-rust" / "src" / "addon_proxy.rs"
# The manifest rules (check_upstream among them) live in the crate the gateway
# and `noo addons check` share (noomesh-internal i302).
MANIFEST_RS = ROOT / "crates" / "addon-manifest" / "src" / "lib.rs"
STEPS = ROOT / "noo-cli" / "src" / "onboard" / "steps.rs"

# add-on → (cert env, key env, client-CA env) its listener reads. The
# server refuses to start with any unset (the evolve add-on's TLS listener).
LISTENER_TLS: dict[str, tuple[str, str, str]] = {
    "evolve": ("NOO_EVOLVE_TLS_CERT", "NOO_EVOLVE_TLS_KEY", "NOO_EVOLVE_TLS_CLIENT_CA"),
}


def _manifests() -> list[dict]:
    """Every HTTP add-on, as {addon, base_url_default}: the rows of
    `addons::ADDONS` that ship a route manifest, dialled at the one upstream
    the gateway accepts for them."""
    text = ADDONS_RS.read_text()
    rows = re.findall(r'Addon \{\s*name: "([a-z_]+)",(.*?)\n    \}', text, re.S)
    out = [
        {"addon": name, "base_url_default": f"https://noo-{name}"}
        for name, body in rows
        if re.search(r"routes_manifest:\s*true", body)
    ]
    assert rows and out, "no HTTP add-ons parsed from addons.rs — every assertion below would be vacuous"
    return out


def test_every_manifest_dials_https() -> None:
    """The gateway refuses any manifest whose upstream is not https://."""
    src = MANIFEST_RS.read_text()
    up = src[src.index("fn check_upstream("):]
    up = up[: up.index("\n}\n")]
    assert 'url.scheme() != "https"' in up, (
        "addon_manifest::check_upstream must refuse a non-https base_url_default: the gateway "
        "sends its bearer on every add-on call, so the door must be mTLS"
    )
    assert "container_of(addon)" in up, "the upstream host must be the add-on's own service"


def test_every_http_addon_has_a_listener_tls_row() -> None:
    missing = [m["addon"] for m in _manifests() if m["addon"] not in LISTENER_TLS]
    assert not missing, (
        f"add-on(s) {missing} have a route manifest but no LISTENER_TLS row here: say which "
        "env vars make their listener serve TLS with a required client certificate"
    )


# test_each_addon_listener_declares_its_mtls_material: moved with the overlay to the add-on repo (N6)


def test_the_leaf_covers_the_host_the_gateway_dials() -> None:
    text = STEPS.read_text()
    svc_list = re.search(r"pub\(crate\) const SVC_LIST: &\[&str\] = &\[(.*?)\];", text, re.S)
    assert svc_list, "SVC_LIST not found in steps.rs"
    for m in _manifests():
        addon = m["addon"]
        host = urlparse(m["base_url_default"]).hostname
        assert f'"{addon}"' in svc_list.group(1), f"onboard never issues a services/{addon} leaf"
        row = re.search(rf'"{re.escape(addon)}"\s*=>\s*&\[([^\]]*)\]', text)
        sans = {addon, "localhost"} | set(re.findall(r'"([^"]+)"', row.group(1) if row else ""))
        assert host in sans, (
            f"the {addon} leaf's SANs {sorted(sans)} do not include {host!r}, the host the "
            "gateway dials — verification would fail on every call"
        )


# test_no_addon_healthcheck_dials_plaintext: moved with the overlay to the add-on repo (N6)


def test_the_proxy_dials_through_the_cluster_client_and_refuses_plaintext() -> None:
    src = PROXY.read_text()
    fwd = src[src.index("async fn forward("):]
    fwd = fwd[: fwd.index("\n}\n")]
    assert "crate::tls::cluster_client()" in fwd, (
        "addon_proxy::forward must dial through tls::cluster_client() — the one client "
        "that presents the gateway leaf and verifies against the cluster CA"
    )
    assert "reqwest::Client::new" not in fwd and "Client::builder" not in fwd
    refuse = fwd.find("plaintext_refusal(")
    send = fwd.find("cluster_client()")
    assert 0 <= refuse < send, "the https check must run before the request is built"


EVOLVE_PATH = os.environ.get("NOO_EVOLVE_PATH", "").strip()


@pytest.mark.skipif(not EVOLVE_PATH, reason="NOO_EVOLVE_PATH names no evolve add-on checkout")
def test_the_evolve_server_requires_a_client_certificate() -> None:
    base = Path(EVOLVE_PATH)
    serve = (base / "src/noo_evolve/serve_tls.py").read_text()
    main = (base / "src/noo_evolve/__main__.py").read_text()
    assert '"ssl_cert_reqs": ssl.CERT_REQUIRED' in serve
    assert "**tls.uvicorn_kwargs()" in main and main.count("uvicorn.run(") == 1
    dev = (base / "docker-compose.evolve.yml").read_text()
    for var in LISTENER_TLS["evolve"]:
        assert f"- {var}=" in dev, f"pai-evolve's dev overlay does not declare {var}"
