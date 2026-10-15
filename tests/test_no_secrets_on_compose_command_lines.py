# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""No compose `command:` or `entrypoint:` interpolates a secret.

Compose expands `${VAR}` in `command:`/`entrypoint:` when the stack comes up,
so the resolved value is baked into the container's `Config.Cmd` — readable
with `docker inspect`, printed by `docker compose config`, and visible in
`/proc/<pid>/cmdline` to every process in the container and every local user in
the docker group. Environment variables are not: `docker inspect` shows them
too, but they never reach argv, and argv is what gets pasted into issues and
scraped by `ps`.

Redis was the live instance (tracker R27):

    command: [--appendonly, "yes", --requirepass, "${REDIS_PASSWORD}"]

It now starts through `docker/redis-entrypoint.sh`, which reads REDIS_PASSWORD
from the environment and writes it into a 0600 config file inside the
container.

The check is on VARIABLE NAMES, not values — the compose file holds no values,
and a name is what a reviewer sees.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
# trellion-intel / evolve overlays: moved with the overlay to the add-on repo (N6).
COMPOSE_FILES = ["docker-compose.cluster.yml", "docker-compose.dist.yml", "docker-compose.trellion.yml", "docker-compose.voice.yml", "docker-compose.gpu-embed.yml"]

# Substrings that mark a variable as carrying a credential.
SECRETY = ("PASSWORD", "PASSPHRASE", "SECRET", "TOKEN", "API_KEY", "_KEY", "CREDENTIAL")

VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)")


def _argv_strings() -> list[tuple[str, str, str, str]]:
    """(file, service, field, string) for every command/entrypoint element."""
    out: list[tuple[str, str, str, str]] = []
    for name in COMPOSE_FILES:
        path = ROOT / name
        # Every listed file must exist: a silent skip is how the evolve
        # overlay went unchecked under its old name for months.
        assert path.is_file(), f"{name} is listed but not in the tree"
        doc = __import__('tests._compose_projection', fromlist=['untag']).untag(__import__('tests._compose_projection', fromlist=['load_raw']).load_raw(path)) or {}
        for svc, body in (doc.get("services") or {}).items():
            for field in ("command", "entrypoint"):
                val = (body or {}).get(field)
                if val is None:
                    continue
                items = val if isinstance(val, list) else [val]
                for item in items:
                    out.append((name, svc, field, str(item)))
    return out


def test_the_parser_actually_found_command_lines() -> None:
    """Guard the guard — a vacuous pass here would hide the next regression."""
    found = _argv_strings()
    assert len(found) > 10, f"expected many command/entrypoint elements, found {len(found)}"


def test_no_credential_variable_appears_in_argv() -> None:
    bad = []
    for file, svc, field, s in _argv_strings():
        for var in VAR_RE.findall(s):
            if any(m in var.upper() for m in SECRETY):
                bad.append(f"  {file}: {svc}.{field} -> ${{{var}}}")
    assert not bad, (
        "a credential is interpolated into a container command line (tracker R27).\n"
        "Pass it as an environment variable and read it in an entrypoint:\n" + "\n".join(bad)
    )


def test_redis_starts_through_the_entrypoint_script() -> None:
    doc = yaml.safe_load((ROOT / "docker-compose.cluster.yml").read_text())
    redis = doc["services"]["redis"]
    assert redis.get("entrypoint") == ["/usr/local/bin/redis-entrypoint.sh"], redis.get("entrypoint")
    assert "command" not in redis, "redis must not carry a command: line again"
    script = ROOT / "docker" / "redis-entrypoint.sh"
    assert script.is_file()
    body = script.read_text()
    # Fail-closed: an empty requirepass DISABLES redis auth.
    assert "REFUSING to start" in body
    # The password goes into a config file, not onto redis-server's argv.
    # (Comments may name the old `--requirepass` form; code may not.)
    code = [ln for ln in body.splitlines() if not ln.lstrip().startswith("#")]
    assert not [ln for ln in code if "--requirepass" in ln], code
    assert any("requirepass ${REDIS_PASSWORD}" in ln for ln in code)
    assert any(ln.startswith("exec redis-server") for ln in code), code[-5:]
