# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A static Prometheus target must name something that runs on every install.

i669: the job `noo_node_agent` scraped `node-agent:8081`, a compose service
that exists only under the `node-agent-compose` profile. On the fleet the agent
is a host unit, so the name never resolved: `up` was 0 for as long as the
metrics went back, and once critical alerts reached the operator (i515b) it
paged hourly. The agents are now listed by the gateway (http_sd). This keeps
the class closed: no static target may name a service that a compose profile
can leave out.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PROM = ROOT / "monitoring/prometheus.yml"


def _compose_files() -> list[Path]:
    return sorted(ROOT.glob("docker-compose*.yml"))


# The profiles that deploy a stack. `monitoring` and the gpu tiers are added
# to one of these, never deployed alone.
DEPLOY_PROFILES = ("controller", "standalone")


def service_profiles() -> dict[str, set[str]]:
    """Each service name (with its container name and network aliases) mapped
    to the profiles that start it. A profile is read only where a file STATES
    one: an overlay that restates a service without `profiles:` does not make
    it run everywhere. A service no file gives a profile is always on (empty
    set)."""
    out: dict[str, set[str]] = {}
    for f in _compose_files():
        doc = yaml.safe_load(f.read_text()) or {}
        for name, svc in (doc.get("services") or {}).items():
            if not isinstance(svc, dict):
                continue
            names = {name}
            if svc.get("container_name"):
                names.add(str(svc["container_name"]))
            nets = svc.get("networks")
            if isinstance(nets, dict):
                for n in nets.values():
                    if isinstance(n, dict):
                        names.update(str(a) for a in n.get("aliases") or [])
            for n in names:
                out.setdefault(n, set()).update(svc.get("profiles") or [])
    return out


def runs_under(profiles: set[str], profile: str) -> bool:
    return not profiles or profile in profiles


def static_targets() -> list[tuple[str, str]]:
    """(job, host) for every static scrape target."""
    doc = yaml.safe_load(PROM.read_text())
    out = []
    for job in doc.get("scrape_configs") or []:
        for sc in job.get("static_configs") or []:
            for t in sc.get("targets") or []:
                out.append((job["job_name"], str(t).rsplit(":", 1)[0]))
    return out


def test_every_static_target_runs_wherever_prometheus_is_deployed() -> None:
    prof = service_profiles()
    assert "prometheus" in prof, "no prometheus service found: this guard is reading the wrong files"
    bad = []
    for job, host in static_targets():
        if host in ("localhost", "127.0.0.1"):
            continue  # Prometheus itself
        if host not in prof:
            bad.append(f"{job}: {host} is not a compose service or alias")
            continue
        for d in DEPLOY_PROFILES:
            if runs_under(prof["prometheus"], d) and not runs_under(prof[host], d):
                bad.append(f"{job}: {host} does not run under `{d}` (its profiles: {sorted(prof[host])}), where prometheus does")
    assert not bad, "a static scrape target names a service that is not there:\n  " + "\n  ".join(bad)


def test_the_guard_would_have_caught_the_old_target() -> None:
    prof = service_profiles()
    assert prof["node-agent"] and all(not runs_under(prof["node-agent"], d) for d in DEPLOY_PROFILES), prof["node-agent"]
    assert static_targets(), "no static targets read: this guard is reading the wrong file"


def test_the_node_agents_come_from_the_gateways_list() -> None:
    doc = yaml.safe_load(PROM.read_text())
    job = next(j for j in doc["scrape_configs"] if j["job_name"] == "noo_node_agent")
    assert "static_configs" not in job
    sd = job["http_sd_configs"]
    assert len(sd) == 1 and sd[0]["url"] == "https://gateway:8080/api/internal/prometheus/targets/node-agents"
    gw = (ROOT / "gateway-rust/src/auth.rs").read_text()
    assert 'SCRAPE_TARGETS_PATH: &str = "/api/internal/prometheus/targets/node-agents"' in gw
    # Both the list and the scrape present the scraper's leaf and verify names.
    for tls in (job["tls_config"], sd[0]["tls_config"]):
        assert tls["cert_file"] == "/app/pki/services/prometheus/service.crt"
        assert tls.get("insecure_skip_verify") is False
