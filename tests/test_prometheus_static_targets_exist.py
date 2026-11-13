# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A static Prometheus target must name something that runs on every install,
and this guard reads the config Prometheus ACTUALLY LOADS.

i669 (#1040) moved the node agents to http_sd, but only in
monitoring/prometheus.yml, while the prometheus service loaded an inline copy
(`configs: prometheus_config` in docker-compose.cluster.yml); the guard read
monitoring/prometheus.yml as well, so it passed against a file nothing
mounted. The loaded copy kept static `node-agent:8081` (never a container on
the fleet: agents are host units) and `nvidia-exporter:9400` (not started on a
CPU-only controller). Docker's DNS has no container to answer for, so every
15 s Prometheus sent both names to the host's own resolver: the 0.6.24-rc.3
rehearsal's idle window counted 84 questions in 5 minutes, and the fleet
carried a standing TargetDown for node-agent:8081.

So:
* the config is found the way Prometheus finds it: `docker compose config`
  (the real merge, tests/_compose_projection.py), the service's
  `--config.file`, and the mount that puts a file at that path. Compose
  resolves the mount's source path; `--no-interpolate` changes nothing here
  (the source is a literal path) and Prometheus does not expand variables in
  its config;
* there is exactly one scrape config in the tree;
* every static target (scrape jobs and the alertmanager) is a service that
  runs wherever Prometheus does AND that no launcher drops at run time.
"""

from __future__ import annotations

import functools
import re
from pathlib import Path

import yaml

from tests._compose_projection import ADDON_OVERLAYS, ROOT, projection

# The profiles that deploy a stack. `monitoring` and the gpu tiers are added
# to one of these, never deployed alone.
DEPLOY_PROFILES = ("controller", "standalone")

# Services a profile lists but a launcher leaves out at run time, so their
# names may have no container behind them. Pinned to the code that decides it
# (test_the_runtime_dropped_set_matches_the_launchers).
RUNTIME_DROPPED = {
    "node-agent": "the host-native agent owns :8081; launchers `--scale node-agent=0`",
    "nvidia-exporter": "started only with an NVIDIA container runtime; `--scale nvidia-exporter=0` otherwise",
}


@functools.lru_cache(maxsize=1)
def _projection() -> dict:
    # what an install runs: the base, the dist overlay and every add-on overlay
    return projection(*ADDON_OVERLAYS, "docker-compose.dist.yml")


def loaded_config_source() -> tuple[str, Path | None, str]:
    """(how, path, text) of the file the prometheus service loads."""
    svc = _projection()["services"]["prometheus"]
    cmd = svc.get("command") or []
    cmd = cmd if isinstance(cmd, list) else str(cmd).split()
    flags = [a for a in cmd if str(a).startswith("--config.file=")]
    assert len(flags) == 1, f"prometheus command has {len(flags)} --config.file flags: {cmd}"
    target = str(flags[0]).split("=", 1)[1]
    hits = []
    for v in svc.get("volumes") or []:
        if isinstance(v, dict) and v.get("target") == target:
            hits.append(("bind", Path(v["source"]), Path(v["source"]).read_text() if v.get("type") == "bind" else ""))
    for c in svc.get("configs") or []:
        if isinstance(c, dict) and c.get("target") == target:
            body = (_projection().get("configs") or {}).get(c["source"]) or {}
            hits.append(("configs", None, body.get("content") or Path(body.get("file", "/nonexistent")).read_text()))
    assert len(hits) == 1, f"{len(hits)} mounts provide {target}: {hits}"
    return hits[0]


def loaded_config() -> dict:
    return yaml.safe_load(loaded_config_source()[2])


@functools.lru_cache(maxsize=1)
def service_profiles() -> dict[str, set[str]]:
    """Each service name (with its container name and network aliases) mapped
    to the profiles that start it; empty set = always on."""
    out: dict[str, set[str]] = {}
    for name, svc in (_projection().get("services") or {}).items():
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


def static_targets(cfg: dict) -> list[tuple[str, str]]:
    """(job, host) for every static target, alertmanagers included."""
    out = []
    for job in cfg.get("scrape_configs") or []:
        for sc in job.get("static_configs") or []:
            for t in sc.get("targets") or []:
                out.append((job["job_name"], str(t).rsplit(":", 1)[0]))
    for am in (cfg.get("alerting") or {}).get("alertmanagers") or []:
        for sc in am.get("static_configs") or []:
            for t in sc.get("targets") or []:
                out.append(("alerting", str(t).rsplit(":", 1)[0]))
    return out


def bad_static_targets(cfg: dict) -> list[str]:
    prof = service_profiles()
    bad = []
    for job, host in static_targets(cfg):
        if host in ("localhost", "127.0.0.1"):
            continue  # Prometheus itself
        if host in RUNTIME_DROPPED:
            bad.append(f"{job}: {host} is dropped at run time ({RUNTIME_DROPPED[host]}): discover it instead")
            continue
        if host not in prof:
            bad.append(f"{job}: {host} is not a compose service or alias")
            continue
        for d in DEPLOY_PROFILES:
            if runs_under(prof["prometheus"], d) and not runs_under(prof[host], d):
                bad.append(f"{job}: {host} does not run under `{d}` (its profiles: {sorted(prof[host])}), where prometheus does")
    return bad


def test_prometheus_loads_monitoring_prometheus_yml() -> None:
    how, path, _ = loaded_config_source()
    assert how == "bind" and path == ROOT / "monitoring/prometheus.yml", (how, path)


def test_there_is_one_scrape_config_in_the_tree() -> None:
    # Two hand-kept copies is how i669 shipped to a file nothing loaded.
    inline = [n for n, c in (_projection().get("configs") or {}).items() if "scrape_configs" in str((c or {}).get("content", ""))]
    assert not inline, f"compose `configs:` {inline} carry a Prometheus config: there must be one copy, monitoring/prometheus.yml"
    holders = []
    for p in ROOT.rglob("*.y*ml"):
        rel = p.relative_to(ROOT).as_posix()
        if rel.startswith((".git/", "node_modules/", ".worktrees/")) or "/node_modules/" in rel or rel.startswith("target/"):
            continue
        try:
            if re.search(r"^\s*scrape_configs:", p.read_text(errors="ignore"), re.M):
                holders.append(rel)
        except OSError:
            continue
    assert holders == ["monitoring/prometheus.yml"], f"Prometheus scrape configs in: {holders}"


def test_every_static_target_runs_wherever_prometheus_is_deployed() -> None:
    prof = service_profiles()
    assert "prometheus" in prof, "no prometheus service found: this guard is reading the wrong files"
    cfg = loaded_config()
    assert static_targets(cfg), "no static targets read: this guard is reading the wrong file"
    bad = bad_static_targets(cfg)
    assert not bad, "a static target names a service that is not there:\n  " + "\n  ".join(bad)


def test_the_guard_would_have_caught_the_old_targets() -> None:
    cfg = loaded_config()
    for job, target in (("noo_node_agent", "node-agent:8081"), ("nvidia_gpu", "nvidia-exporter:9400")):
        old = {**cfg, "scrape_configs": [*cfg["scrape_configs"], {"job_name": job, "static_configs": [{"targets": [target]}]}]}
        assert any(target.split(":")[0] in b for b in bad_static_targets(old)), f"{target} would pass the guard"


def test_the_runtime_dropped_set_matches_the_launchers() -> None:
    sh = (ROOT / "noo-cli/src/onboard/sh.rs").read_text()
    start = (ROOT / "scripts/noomesh-start.sh").read_text()
    assert 'HOST_OWNED_SERVICES: &[&str] = &["node-agent"]' in sh
    assert 'GPU_ONLY_SERVICES: &[&str] = &["nvidia-exporter"]' in sh
    for svc in RUNTIME_DROPPED:
        assert f'--scale {svc}=0' in start, f"noomesh-start.sh no longer scales {svc} to 0: update RUNTIME_DROPPED"


def test_the_node_agents_come_from_the_gateways_list() -> None:
    job = next(j for j in loaded_config()["scrape_configs"] if j["job_name"] == "noo_node_agent")
    assert "static_configs" not in job
    sd = job["http_sd_configs"]
    assert len(sd) == 1 and sd[0]["url"] == "https://gateway:8080/api/internal/prometheus/targets/node-agents"
    gw = (ROOT / "gateway-rust/src/auth.rs").read_text()
    assert 'SCRAPE_TARGETS_PATH: &str = "/api/internal/prometheus/targets/node-agents"' in gw
    # Both the list and the scrape present the scraper's leaf and verify names.
    for tls in (job["tls_config"], sd[0]["tls_config"]):
        assert tls["cert_file"] == "/app/pki/services/prometheus/service.crt"
        assert tls.get("insecure_skip_verify") is False


def test_the_gpu_exporter_is_discovered_from_its_own_announcement() -> None:
    job = next(j for j in loaded_config()["scrape_configs"] if j["job_name"] == "nvidia_gpu")
    assert "static_configs" not in job
    assert job["file_sd_configs"] == [{"files": ["/etc/prometheus/sd/*.json"], "refresh_interval": "30s"}]
    services = _projection()["services"]
    prom_mounts = {v.get("target"): v for v in services["prometheus"].get("volumes") or [] if isinstance(v, dict)}
    exp_mounts = {v.get("target"): v for v in services["nvidia-exporter"].get("volumes") or [] if isinstance(v, dict)}
    assert prom_mounts["/etc/prometheus/sd"]["source"] == "prometheus-sd" and prom_mounts["/etc/prometheus/sd"].get("read_only") is True
    assert exp_mounts["/run/noo-prom-sd"]["source"] == "prometheus-sd" and not exp_mounts["/run/noo-prom-sd"].get("read_only")
    env = services["nvidia-exporter"].get("environment") or {}
    env = env if isinstance(env, dict) else dict(str(e).split("=", 1) for e in env)
    assert env.get("NOO_PROM_SD_DIR") == "/run/noo-prom-sd"
    # a tmpfs: empty whenever nothing that uses it runs, so no stale target
    opts = (_projection()["volumes"]["prometheus-sd"] or {}).get("driver_opts") or {}
    assert opts.get("type") == "tmpfs" and "uid=65532" in str(opts.get("o")), opts
