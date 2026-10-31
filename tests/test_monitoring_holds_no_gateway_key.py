# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The monitoring stack must not hold the controller's identity.

an earlier change / §3f R28.

`gateway/gateway.crt` carries ``O="Mesh Cluster Gateway"``, and that org is
the whole basis on which a node agent decides a caller is the controller
(``node-agent-go/internal/auth/principal.go``). Prometheus mounted the entire
PKI directory and named ``gateway/gateway.key`` in four scrape jobs; promtail
(retired in fleet logging phase 4) named it in its env. So two containers whose jobs are "GET some URLs" and
"ship some logs" held a credential good for ``/start``, ``/stop``, ``/clean``,
``/pull``, ``/api/skills/run`` and ``/logs/{container}`` on every node.

These tests fail if that comes back by the config. The mount half — a
narrowed config over a wide mount leaves the key one ``cat`` away — is
tests/test_pki_mounts_are_narrow.py, for every service.
"""

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE = REPO_ROOT / "docker-compose.cluster.yml"

# The controller's OWN processes. These are what "Mesh Cluster Gateway"
# means: they are the controller, so holding its leaf is not a privilege
# escalation, it is their identity. Nothing else belongs here, and adding a
# name is a decision someone has to make in a diff. trellion, trellion-intel,
# worker and worker-extra left in the design (their own leaves) —
# tests/test_addons_present_own_leaf.py. The gateway is the one holder.
CONTROLLER_SERVICES = {
    "gateway",
}

MONITORING_SERVICES = {
    "prometheus",
    "grafana",
    "alertmanager",
    "loki",
    "tempo",
    "node-exporter",
    "nvidia-exporter",
}


@pytest.fixture(scope="module")
def compose():
    # Base + add-on overlays, composed: trellion-intel lives in an overlay
    # that `extends` trellion.
    from tests._compose_projection import full_projection
    return full_projection()


def _env_values(svc):
    env = svc.get("environment") or []
    if isinstance(env, dict):
        return [f"{k}={v}" for k, v in env.items()]
    return list(env)


def _volume_strings(svc):
    """`source:target[:mode]` for every mount. The projection renders mounts
    long-form; re-join them so the checks below read one shape."""
    out = []
    for v in svc.get("volumes") or []:
        if isinstance(v, str):
            out.append(v)
        else:
            out.append(":".join(str(v.get(k, "")) for k in ("source", "target") if v.get(k)))
    return out


def test_only_the_controllers_own_services_name_the_gateway_key(compose):
    holders = set()
    for name, svc in compose["services"].items():
        blob = "\n".join(_env_values(svc) + _volume_strings(svc) + list(svc.get("command") or []))
        if "gateway/gateway.key" in blob:
            holders.add(name)

    # Guard against a vacuous pass: if NOTHING names the key, this test has
    # stopped testing anything (a rename, a refactor, a moved file).
    assert holders, (
        "no service names gateway/gateway.key at all — this assertion is no "
        "longer looking at the thing it was written to look at"
    )
    assert holders <= CONTROLLER_SERVICES, (
        f"{sorted(holders - CONTROLLER_SERVICES)} mount or name the controller's "
        "private key. That leaf is what a node agent reads as 'this caller may "
        "command me'. Issue the service its own leaf instead: "
        "`noo security pki issue-service <name>`."
    )


def test_no_monitoring_service_names_the_gateway_key(compose):
    for name in MONITORING_SERVICES:
        svc = compose["services"].get(name)
        assert svc is not None, f"{name} vanished from compose — update this test"
        blob = "\n".join(_env_values(svc) + _volume_strings(svc))
        assert "gateway/gateway" not in blob, (
            f"{name} references the gateway leaf; it must use "
            f"services/{name}/service.crt (O=\"Mesh Cluster Service\")"
        )


# The mount check that lived here (prometheus/promtail/grafana only) is now
# tests/test_pki_mounts_are_narrow.py, over every service in every file.


def test_every_prometheus_scrape_job_uses_the_service_leaf(compose):
    raw = compose["configs"]["prometheus_config"]["content"]
    cfg = yaml.safe_load(raw)
    jobs = cfg["scrape_configs"]
    assert jobs, "the inline prometheus config has no scrape jobs"
    for job in jobs:
        tls = job.get("tls_config") or {}
        assert tls.get("cert_file") == "/app/pki/services/prometheus/service.crt", (
            f"job {job['job_name']!r} scrapes with {tls.get('cert_file')!r}"
        )
        assert tls.get("key_file") == "/app/pki/services/prometheus/service.key", (
            f"job {job['job_name']!r} scrapes with {tls.get('key_file')!r}"
        )


def test_the_reference_prometheus_config_agrees_with_the_inline_one():
    ref = yaml.safe_load((REPO_ROOT / "monitoring" / "prometheus.yml").read_text())
    for job in ref["scrape_configs"]:
        tls = job.get("tls_config") or {}
        assert "gateway" not in str(tls.get("cert_file", "")), (
            f"monitoring/prometheus.yml job {job['job_name']!r} still scrapes as "
            "the controller; it is copied into standalone deployments"
        )
