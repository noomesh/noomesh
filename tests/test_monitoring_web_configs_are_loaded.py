# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every mounted monitoring `web-config.yml` is LOADED by its service.

Found 2026-09-29 in a read-only sweep of `dev`. `docker-compose.cluster.yml`
mounted `monitoring/alertmanager/web-config.yml` (TLS + a required cluster-CA
client certificate) into the alertmanager container — and its `command:`
never passed `--web.config.file=`. The Prometheus-family servers only read
that file when told to, so :9093 answered plain HTTP with no client auth on
127.0.0.1 AND on the compose network, while Prometheus was configured to
dial it as `scheme: https` (the alerting pipeline was silently broken and
the door was open, in one line). Proven against the real image before the
fix: plaintext `/-/healthy` → 200; after: 400, `certificate required`
without a leaf, 200 with one.

A mount is a declaration ("this listener is mTLS"); the flag is what makes
it true. This guard reads the raw compose file (the projection is not
needed: `command:` and `volumes:` are literal here) and, for every service
that mounts a file named `web-config.yml`, requires the container path to
appear as `--web.config.file=<path>` in that service's command, and the
host file to require a client certificate. It also pins the alertmanager
healthcheck to the mTLS listener (amtool with the container's own leaf).

Planted: the `--web.config.file` line removed from alertmanager → the first
test fails naming it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tests._compose_projection import BASE, load_raw, untag

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def services() -> dict:
    svcs = untag(load_raw(BASE)).get("services") or {}
    assert len(svcs) > 20, "the compose parse found almost nothing — vacuous"
    return svcs


def _web_config_mounts(service: dict) -> list[tuple[str, str]]:
    """(host path, container path) for every `web-config.yml` mount."""
    out = []
    for vol in service.get("volumes") or []:
        if isinstance(vol, dict):
            src, dst = vol.get("source", ""), vol.get("target", "")
        else:
            parts = str(vol).split(":")
            src, dst = (parts[0], parts[1]) if len(parts) >= 2 else ("", "")
        if Path(dst).name == "web-config.yml":
            out.append((src, dst))
    return out


def _command_text(service: dict) -> str:
    cmd = service.get("command")
    if cmd is None:
        return ""
    return " ".join(cmd) if isinstance(cmd, list) else str(cmd)


def test_every_web_config_mount_is_named_by_the_command(services: dict) -> None:
    found: list[str] = []
    for name, svc in services.items():
        for _src, dst in _web_config_mounts(svc):
            found.append(name)
            flag = f"--web.config.file={dst}"
            assert flag in _command_text(svc), (
                f"{name} mounts {dst} but its command never passes {flag!r}: "
                "the listener is plain HTTP with no client auth"
            )
    assert "alertmanager" in found, "the service this guard was written for is no longer checked"
    assert "prometheus" in found
    assert len(found) >= 3, found


def test_every_mounted_web_config_requires_a_client_certificate(services: dict) -> None:
    checked = 0
    for name, svc in services.items():
        for src, _dst in _web_config_mounts(svc):
            host = (ROOT / src).resolve()
            assert host.is_file(), f"{name}: {src} is mounted but not in the tree"
            doc = yaml.safe_load(host.read_text()) or {}
            tls = doc.get("tls_server_config") or {}
            assert tls.get("cert_file") and tls.get("key_file"), f"{src}: no server leaf"
            assert tls.get("client_ca_file"), f"{src}: no client CA — nothing to verify a client against"
            assert tls.get("client_auth_type") == "RequireAndVerifyClientCert", (
                f"{src}: client_auth_type={tls.get('client_auth_type')!r}, not RequireAndVerifyClientCert"
            )
            checked += 1
    assert checked >= 3, checked


def test_the_alertmanager_healthcheck_probes_the_mtls_listener(services: dict) -> None:
    """The image has no shell, wget or curl; the probe is amtool presenting
    the container's own leaf over https. A `disable: true` here would be the
    Loki compromise; a plaintext probe could not succeed at all."""
    hc = services["alertmanager"].get("healthcheck") or {}
    test = hc.get("test") or []
    assert test and test[0] == "CMD", hc
    joined = " ".join(test[1:])
    assert "amtool" in joined and "https://localhost:9093" in joined, joined
    cfg_flag = next((a for a in test if a.startswith("--http.config.file=")), None)
    assert cfg_flag, "amtool needs --http.config.file to present a client certificate"
    cfg_path = cfg_flag.split("=", 1)[1]
    mounts = {str(v).split(":")[1]: str(v).split(":")[0] for v in services["alertmanager"]["volumes"] if ":" in str(v)}
    assert cfg_path in mounts, f"{cfg_path} is not mounted into the container"
    doc = yaml.safe_load((ROOT / mounts[cfg_path]).read_text()) or {}
    tls = doc.get("tls_config") or {}
    assert tls.get("cert_file") and tls.get("key_file") and tls.get("ca_file"), tls
    assert tls.get("insecure_skip_verify") in (None, False)


# ── Who may present a leaf ──────────────────────────────────────────────
#
# RequireAndVerifyClientCert admits ANY cluster-CA leaf, node leaves
# included; Alertmanager can create silences. exporter-toolkit's
# `client_allowed_sans` narrows it: one of the leaf's SANs (DNS/IP/e-mail/URI;
# never the CN) must EXACTLY equal an entry (web/tls_config.go,
# `slices.Contains`). The lists below are the callers found in the tree:
#
#   prometheus   <- gateway (/api/metrics/query, grafana-ds proxy via the
#                   gateway leaf, NOO_TLS_CERT=gateway.crt), prometheus
#                   (self-scrape job with services/prometheus)
#   alertmanager <- prometheus (alerting push), gateway (noo_alerts_list),
#                   alertmanager's own amtool healthcheck (own leaf)
#
# Grafana reaches Prometheus only through the gateway
# (configs/grafana/datasources/prometheus.yml); trellion carries
# NOO_PROMETHEUS_URL but no code in it dials Prometheus.
EXPECTED_ALLOWED_SANS = {
    "monitoring/prometheus/web-config.yml": ["noo-gateway", "prometheus"],
    "monitoring/alertmanager/web-config.yml": ["alertmanager", "noo-gateway", "prometheus"],
}


def _allowed(rel: str) -> list[str]:
    doc = yaml.safe_load((ROOT / rel).read_text()) or {}
    sans = (doc.get("tls_server_config") or {}).get("client_allowed_sans")
    assert isinstance(sans, list) and sans, f"{rel}: no client_allowed_sans - any cluster-CA leaf is admitted"
    return sans


@pytest.mark.parametrize("rel", sorted(EXPECTED_ALLOWED_SANS))
def test_web_config_allows_only_the_known_callers(rel: str) -> None:
    sans = _allowed(rel)
    assert sorted(sans) == EXPECTED_ALLOWED_SANS[rel], sans
    for s in sans:
        assert isinstance(s, str) and "*" not in s and s.strip() == s, f"{rel}: {s!r} is not an exact name"
        assert s != "localhost", "every leaf carries localhost"
    # A node leaf is `CN=<node id>, O=Mesh Cluster Node` with the node id as
    # its SAN; none of the allowed names may be a node-shaped name.
    assert not [s for s in sans if s.endswith(".ts.net") or s[:1].isupper()], sans


def test_alertmanager_list_contains_the_gateway_and_prometheus() -> None:
    sans = _allowed("monitoring/alertmanager/web-config.yml")
    assert {"noo-gateway", "prometheus"} <= set(sans)


def test_the_allowed_names_are_sans_the_issuers_really_mint() -> None:
    """The names are not invented: the gateway leaf always carries
    `noo-gateway`, and a service leaf carries `<service>` as a DNS SAN."""
    pki = (ROOT / "noo-cli" / "src" / "pki.rs").read_text()
    gw = pki[pki.index("pub fn issue_gateway_cert") : pki.index("pub fn issue_service_cert")]
    assert '"noo-gateway".into()' in gw, "the gateway leaf no longer carries the SAN the allow-lists name"
    svc = pki[pki.index("pub fn issue_service_cert") : pki.index("pub fn issue_service_cert") + 2500]
    assert "service" in svc and "Mesh Cluster Service" in svc
    ca = (ROOT / "src" / "noomesh" / "pki" / "ca.py").read_text()
    assert "dns_sans=[service," in ca


def test_the_web_configs_are_mounted_and_loaded_for_the_allowlist_to_matter(services: dict) -> None:
    for name, rel in (("prometheus", "monitoring/prometheus/web-config.yml"), ("alertmanager", "monitoring/alertmanager/web-config.yml")):
        mounts = [src for src, _ in _web_config_mounts(services[name])]
        assert any(m.lstrip("./") == rel for m in mounts), (name, mounts)
