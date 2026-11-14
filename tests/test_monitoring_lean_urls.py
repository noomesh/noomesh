# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""On a lean install the gateway and the worker get EMPTY Loki and Tempo
addresses; on every other install compose's defaults apply exactly as before.

Compose sets `NOO_LOKI_URL`, `NOO_TEMPO_OTLP_URL` and `NOO_TEMPO_URL` on the
gateway and the worker as `${VAR-default}`: unset takes the in-stack default,
EMPTY stays empty (the old `:-` turned an empty value back into the default,
so a lean install still dialed tempo:4318 and loki:3100). The launcher's
`derive_profile_env` (every launcher calls it before compose) exports the
three empty when the EFFECTIVE level is lean: the gateway then logs "summary
rows only, no spans exported", log search answers "off by choice", and the
worker skips tracing and the Loki security audit.

UNSET = FULL: with no `cluster.monitoring` nothing is exported.

Planted mutant: in lib-config.sh `monitoring_derive_env`,
`""|"$_def"|"$_def/") export "$_var="` -> `export "$_var=$_def"` turns
`test_lean_exports_the_three_empty` red.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "scripts" / "lib-config.sh"
COMPOSE = ROOT / "docker-compose.cluster.yml"
VARS = ("NOO_LOKI_URL", "NOO_TEMPO_OTLP_URL", "NOO_TEMPO_URL")
SHOW = 'derive_profile_env; printf "%s|%s|%s" "${NOO_LOKI_URL-UNSET}" "${NOO_TEMPO_OTLP_URL-UNSET}" "${NOO_TEMPO_URL-UNSET}"'


def _bash(tmp_path: Path, yaml: str | None, env_extra: dict | None = None, body: str = SHOW) -> subprocess.CompletedProcess:
    if yaml is not None:
        (tmp_path / "noomesh.yaml").write_text(yaml)
    drop = ("COMPOSE_PROFILES", "NOO_CLI_BIN", "NOO_CONTAINER_PREFIX", "PROFILE_ARGS", *VARS)
    env = {k: v for k, v in os.environ.items() if k not in drop}
    env["PATH"] = ":".join(p for p in env.get("PATH", "").split(":") if not (Path(p) / "noo").exists())
    env.update(env_extra or {})
    return subprocess.run(["bash", "-c", f". {LIB}\n{body}"], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=30)


def test_lean_exports_the_three_empty(tmp_path):
    r = _bash(tmp_path, "cluster:\n  monitoring: lean\n")
    assert r.returncode == 0, r
    assert r.stdout == "||", f"lean must export NOO_LOKI_URL, NOO_TEMPO_OTLP_URL and NOO_TEMPO_URL empty: {r.stdout!r}"


def test_unset_and_full_export_nothing(tmp_path):
    for yaml in ("cluster:\n  default_backend: vllm\n", "cluster:\n  monitoring: full\n", "cluster:\n  monitoring: Lean\n", None):
        r = _bash(tmp_path, yaml)
        assert r.stdout == "UNSET|UNSET|UNSET", f"{yaml!r}: compose's defaults must apply: {r.stdout!r}"
        (tmp_path / "noomesh.yaml").unlink(missing_ok=True)


def test_an_in_stack_value_is_blanked_and_an_operators_own_is_kept(tmp_path):
    r = _bash(tmp_path, "cluster:\n  monitoring: lean\n",
              env_extra={"NOO_LOKI_URL": "https://loki:3100", "NOO_TEMPO_URL": "https://tempo.example:3200"})
    assert r.stdout == "||https://tempo.example:3200", r.stdout
    assert "NOO_TEMPO_URL=https://tempo.example:3200 points elsewhere; kept" in r.stderr


def test_what_outranks_lean_keeps_the_addresses(tmp_path):
    lean = "cluster:\n  monitoring: lean\n"
    r = _bash(tmp_path, lean, env_extra={"COMPOSE_PROFILES": "monitoring"})
    assert r.stdout == "UNSET|UNSET|UNSET", "COMPOSE_PROFILES runs the set: it must be reachable"
    r = _bash(tmp_path, lean, env_extra={"PROFILE_ARGS": "--profile controller"})
    assert r.stdout == "UNSET|UNSET|UNSET", "the controller profile runs the set"


def _env_lines(service: str) -> list[str]:
    text = COMPOSE.read_text()
    m = re.search(rf"^  {service}:\n(.*?)(?=^  [a-z0-9-]+:\n)", text, re.M | re.S)
    assert m, f"no {service} service block"
    return [l.strip() for l in m.group(1).splitlines() if re.match(r"\s*- NOO_(LOKI|TEMPO)_(OTLP_)?URL=", l)]


def test_compose_keeps_an_empty_address_empty():
    seen = 0
    for svc in ("gateway", "worker"):
        for line in _env_lines(svc):
            seen += 1
            var = line.split("=", 1)[0].lstrip("- ")
            assert f"=${{{var}-https://" in line, f"{svc}: {line!r} must be `${{{var}-default}}` (empty stays empty)"
            assert ":-" not in line.split("#")[0], f"{svc}: {line!r} turns a lean install's empty value back into the default"
    assert seen == 5, f"expected the gateway's three and the worker's two address lines, saw {seen}"


def test_every_launcher_derives_before_compose():
    for name in ("noomesh-start.sh", "noomesh-restart.sh", "noomesh-rebuild.sh"):
        assert "derive_profile_env" in (ROOT / "scripts" / name).read_text(), name
    lib = LIB.read_text()
    body = lib.split("derive_profile_env() {", 1)[1]
    assert body.lstrip().startswith("monitoring_derive_env"), "it must run before the embed-cpu early return"
