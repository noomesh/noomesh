# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every controller runs the core of the monitoring set; Grafana, Loki and
Tempo are a declared choice.

2026-11 (PR a of the opt-in change): Prometheus, Alertmanager and
node-exporter stay on the `standalone` profile, so every install runs them.
Loki, Tempo and Grafana left it: they carry `monitoring` and `controller`
only, and the launcher adds `--profile monitoring` unless noomesh.yaml says
`cluster.monitoring: lean` (unset = full: the live controller is a standalone
install, tests/test_monitoring_lean_launcher.py pins that). The history below
is why the choice is a persisted declaration and never a one-shot flag.

Fleet logging phase 0 (2026-09-28). The live controller (a standalone
install, `NOO_DEFAULT_PROFILE=standalone`) ran 13 containers and not one of
loki, prometheus, alertmanager, grafana or node-exporter (nor, then,
promtail and its socket proxy — retired in phase 4, the node-agent ships), because those services carried the `controller` profile only
and standalone's opt-in (`noo onboard --with-monitoring`, a one-shot
`--profile monitoring`) persisted nothing: the first `noo upgrade --stack`
relaunched under the standalone profile and dropped the set. Loki's data
directory was 4 KB three weeks after onboarding.

Two declarations say what a controller runs, and neither can see the other:

* `docker-compose.cluster.yml` — each service's `profiles:`;
* `noo-cli/src/onboard/sh.rs` — `HOST_OWNED_SERVICES` / `GPU_ONLY_SERVICES`,
  the only way a projected service stays out of what onboard starts and
  recreates (the wizard reads the projection itself since this date; before
  it a fixed list of six).

This guard reads the compose projection for BOTH profiles and the Rust
exclusion lists, and fails when an always-on monitoring service is absent
from either profile, an optional one is back on `standalone` (it would run on
a lean install), or one is named in an exclusion. Planted: `standalone`
removed from prometheus's profiles → the first test fails; `"loki"` added to
HOST_OWNED_SERVICES → the onboard test fails.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests._compose_projection import BASE, load_raw, untag

ROOT = Path(__file__).resolve().parents[1]
SH_RS = ROOT / "noo-cli" / "src" / "onboard" / "sh.rs"
STEPS_RS = ROOT / "noo-cli" / "src" / "onboard" / "steps.rs"
LAUNCHER = ROOT / "scripts" / "noomesh-start.sh"
MANUAL = ROOT / "docs" / "operating" / "operator-manual.md"

# Always on: metrics and alerts, on every install.
ALWAYS = {"prometheus", "alertmanager", "node-exporter"}
# Optional (about 250 MiB idle): on unless `cluster.monitoring: lean`.
OPTIONAL = {"loki", "tempo", "grafana"}
MONITORING = ALWAYS | OPTIONAL
# Runs on a controller with a GPU; the launcher scales it to 0 without the
# NVIDIA runtime, onboard leaves it out then. In both profiles all the same.
GPU_MONITORING = {"nvidia-exporter"}


@pytest.fixture(scope="module")
def services() -> dict:
    svcs = untag(load_raw(BASE)).get("services") or {}
    assert len(svcs) > 20, "the compose parse found almost nothing — vacuous"
    return svcs


def _with_profile(services: dict, profile: str) -> set[str]:
    return {n for n, s in services.items() if profile in (s.get("profiles") or [])}


# Retired, and must stay retired: promtail streamed every container's
# stdout through a read-only Docker socket proxy; since fleet logging phase 4
# (2026-09-28) the controller's own node-agent ships those lines through the
# gateway (`source="docker"`), like every node's. Re-adding either service
# re-adds a Docker-API holder to the stack.
RETIRED = {"promtail", "docker-socket-proxy"}


def test_the_always_on_set_is_in_both_profiles_and_the_optional_set_is_declared(services):
    controller = _with_profile(services, "controller")
    standalone = _with_profile(services, "standalone")
    back = RETIRED & set(services)
    assert not back, (
        f"{sorted(back)} are back in compose — retired with fleet logging phase 4; "
        "the node-agent on the controller ships container logs (#526)"
    )
    assert MONITORING | GPU_MONITORING <= controller, sorted((MONITORING | GPU_MONITORING) - controller)
    assert ALWAYS | GPU_MONITORING <= standalone, (
        "always-on monitoring services missing from the standalone profile — a standalone "
        f"controller would not run them: {sorted((ALWAYS | GPU_MONITORING) - standalone)}"
    )
    assert not OPTIONAL & standalone, (
        f"{sorted(OPTIONAL & standalone)} are on the standalone profile again: a lean install "
        "(cluster.monitoring: lean) would run them anyway"
    )
    on_switch = _with_profile(services, "monitoring")
    assert MONITORING <= on_switch, f"the launcher's --profile monitoring misses {sorted(MONITORING - on_switch)}"


def test_standalone_is_the_controller_profile_plus_its_embedder(services):
    """The two install shapes run the same product. The only services one
    has and the other lacks are the standalone box's local embedder and its
    mTLS sidecar, and the optional monitoring three, which a standalone
    install gets from `--profile monitoring` (cluster.monitoring, unset =
    full); a new controller-only service is a decision to make here, by
    name."""
    controller = _with_profile(services, "controller")
    standalone = _with_profile(services, "standalone")
    assert controller - standalone == OPTIONAL, sorted(controller - standalone)
    assert standalone - controller == {"ollama-embed", "stunnel-ollama-embed"}, sorted(standalone - controller)
    # The exact set, so a service that joins either profile is a decision
    # made here by name — and one that leaves (promtail) cannot drift back.
    assert controller == EXPECTED_CONTROLLER, sorted(controller ^ EXPECTED_CONTROLLER)


# What the `controller` profile projects today, by name.
EXPECTED_CONTROLLER = {
    "gateway", "worker", "worker-extra", "sandbox", "sandbox-extra",
    "postgres", "redis", "nats", "model-cache",
} | MONITORING | GPU_MONITORING


def _rust_const_list(src: str, name: str) -> list[str]:
    m = re.search(rf"const {name}: &\[&str\] = &\[([^\]]*)\];", src)
    assert m, f"{name} not found in sh.rs — the grep is stale, not the list"
    return re.findall(r'"([^"]+)"', m.group(1))


def test_onboard_derives_its_service_set_and_excludes_no_monitoring_service():
    sh = SH_RS.read_text()
    host_owned = _rust_const_list(sh, "HOST_OWNED_SERVICES")
    gpu_only = _rust_const_list(sh, "GPU_ONLY_SERVICES")
    assert host_owned == ["node-agent"], host_owned
    assert gpu_only == ["nvidia-exporter"], gpu_only
    leaked = MONITORING & (set(host_owned) | set(gpu_only))
    assert not leaked, f"monitoring services excluded from what onboard recreates: {sorted(leaked)}"
    steps = STEPS_RS.read_text()
    assert "profile_services(ctx, \"controller\")" in steps, (
        "onboard no longer reads the compose projection for its service set"
    )
    assert 'recreate_args(ctx, &["postgres", "redis", "nats", "node-agent", "trellion", "gateway"])' not in steps, (
        "the fixed six are back — the monitoring set would never be recreated"
    )


def test_the_launcher_guards_grafanas_password_on_the_standalone_profile():
    """Grafana rides the standalone profile now, so the launcher's fail-closed
    check on GRAFANA_PASSWORD must fire there too — or standalone boots
    Grafana with an empty admin password."""
    body = LAUNCHER.read_text()
    m = re.search(r'grep -qE "([^"]*)"; then\n\s+for _reqvar in GRAFANA_PASSWORD', body)
    assert m, "the GRAFANA_PASSWORD guard moved — update this grep, not the guard"
    assert "standalone" in m.group(1).split("|"), m.group(1)


def test_the_operator_manual_says_what_the_compose_file_does():
    body = MANUAL.read_text()
    assert "Monitoring is part of" in body, "the manual's monitoring sentence moved — update this grep"
    after = body.split("Monitoring is part of")[1][:600]
    assert "standalone" in after, "operator-manual.md's monitoring sentence must say standalone runs it too"
    assert "cluster.monitoring" in after and "noo stack monitoring" in after, (
        "the manual must say Grafana, Loki and Tempo are a declared choice, and how to change it"
    )
