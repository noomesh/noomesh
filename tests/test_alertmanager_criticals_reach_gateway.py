# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Critical alerts reach the gateway's intake; everything else stays 'null' (i515b).

Until i515b every Alertmanager route, criticals included, ended at the
no-op 'null' receiver: a critical fired, showed in the UI, and nobody was
told. The critical route now names the `gateway` receiver, a webhook to
`POST /api/alerts/alertmanager` that raises the operator's persisting
operator_alert. Pinned here:

  - the default route stays 'null' (warnings are not a notification);
  - the severity="critical" route's receiver is not 'null';
  - that receiver posts to /api/alerts/alertmanager with send_resolved
    (without it a condition is raised and never cleared);
  - it dials with Alertmanager's own service leaf, the only credential the
    intake admits (`auth::is_alert_intake`), which compose mounts at
    /app/pki/services/alertmanager.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "monitoring" / "alertmanager" / "alertmanager.yml"
COMPOSE = ROOT / "docker-compose.cluster.yml"
AUTH_RS = ROOT / "gateway-rust" / "src" / "auth.rs"
INTAKE_PATH = "/api/alerts/alertmanager"
LEAF_DIR = "/app/pki/services/alertmanager/"


def _config() -> dict:
    doc = yaml.safe_load(CONFIG.read_text()) or {}
    assert doc.get("route"), "alertmanager.yml parsed with no route — the checks below would be vacuous"
    return doc


def _critical_route(doc: dict) -> dict:
    routes = doc["route"].get("routes") or []
    hits = [r for r in routes if 'severity = "critical"' in (r.get("matchers") or [])]
    assert len(hits) == 1, f"expected exactly one severity=critical route, found {len(hits)}: {routes}"
    return hits[0]


def _receiver(doc: dict, name: str) -> dict:
    hits = [r for r in doc.get("receivers") or [] if r.get("name") == name]
    assert len(hits) == 1, f"receiver {name!r} is defined {len(hits)} times"
    return hits[0]


def test_the_default_route_stays_null() -> None:
    doc = _config()
    assert doc["route"]["receiver"] == "null", "non-critical alerts must not notify"
    assert _receiver(doc, "null") == {"name": "null"}, "the 'null' receiver must stay a no-op"


def test_the_critical_route_reaches_the_gateway_intake() -> None:
    doc = _config()
    name = _critical_route(doc).get("receiver")
    assert name and name != "null", f"criticals are routed to {name!r}: nobody hears about them"
    hooks = _receiver(doc, name).get("webhook_configs") or []
    assert len(hooks) == 1, f"receiver {name!r} has {len(hooks)} webhooks; expected the one intake"
    hook = hooks[0]
    assert hook.get("url") == f"https://gateway:8080{INTAKE_PATH}", hook.get("url")
    assert hook.get("send_resolved") is True, "without send_resolved a raised condition never clears"
    tls = (hook.get("http_config") or {}).get("tls_config") or {}
    assert tls.get("cert_file", "").startswith(LEAF_DIR), tls
    assert tls.get("key_file", "").startswith(LEAF_DIR), tls
    assert tls.get("ca_file") == "/app/pki/ca.crt", tls
    assert not tls.get("insecure_skip_verify"), tls


def test_the_leaf_and_path_are_the_ones_the_gateway_admits() -> None:
    compose = COMPOSE.read_text()
    assert f":{LEAF_DIR.rstrip('/')}:ro" in compose, "compose no longer mounts Alertmanager's service leaf"
    auth = AUTH_RS.read_text()
    assert f'pub const ALERT_INTAKE_PATH: &str = "{INTAKE_PATH}";' in auth
    assert 'pub const ALERT_INTAKE_SERVICE: &str = "alertmanager";' in auth
