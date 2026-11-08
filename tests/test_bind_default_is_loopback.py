# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The cluster-plane bind fails closed: compose's default is loopback (i515a).

The launchers and noo-hostd's recreate derive NOO_BIND_ADDR from
NOO_BIND_MODE (scripts/lib-bind-addr.sh) and refuse an unset mode. The
compose default only applies to a run that bypasses them, so it must be
127.0.0.1: that run is then reachable from this machine only, never on every
interface. It was `:-0.0.0.0`, which published the gateway, NATS, the node
agent, the sensor agent, the exporters and the model cache everywhere.

0.0.0.0 is only ever the written-down NOO_BIND_MODE=all, resolved by the
launcher. No compose file the CLI ships may name it as a host address.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BUILD_RS = REPO / "noo-cli" / "build.rs"

BIND = re.compile(r"\$\{NOO_BIND_ADDR([^}]*)\}")
# A published port whose host part is the literal every-interface address.
OPEN = re.compile(r"""["']?(?:0\.0\.0\.0|\[::\]):\$?\{?[A-Z0-9_:\-]*\}?:?\d*""")


def _shipped() -> list[Path]:
    """The compose files the CLI bundles (noo-cli/build.rs), as they exist."""
    names = re.findall(r'"(docker-compose[^"/]*\.ya?ml)"', BUILD_RS.read_text())
    files = [REPO / n for n in dict.fromkeys(names) if (REPO / n).is_file()]
    assert any(f.name == "docker-compose.cluster.yml" for f in files), (
        f"read only {[f.name for f in files]} from noo-cli/build.rs: this guard is looking in the wrong place"
    )
    return files


def _code_lines(path: Path):
    for no, line in enumerate(path.read_text().splitlines(), 1):
        code = line.split("#", 1)[0]
        if code.strip():
            yield no, code


def test_every_bind_default_is_loopback():
    seen, bad = 0, []
    for f in _shipped():
        for no, code in _code_lines(f):
            for m in BIND.finditer(code):
                seen += 1
                if m.group(1) != ":-127.0.0.1":
                    bad.append(f"{f.name}:{no}: ${{NOO_BIND_ADDR{m.group(1)}}}")
    assert seen >= 7, f"found only {seen} NOO_BIND_ADDR publishes: the walk is broken, not the code"
    assert not bad, (
        "a cluster-plane publish does not default to loopback; a compose run that bypasses the "
        "launcher would publish it on that address (use ${NOO_BIND_ADDR:-127.0.0.1}):\n  " + "\n  ".join(bad)
    )


def test_no_shipped_compose_file_publishes_on_every_interface():
    bad = []
    for f in _shipped():
        for no, code in _code_lines(f):
            if OPEN.search(code) and ("ports" in code or code.lstrip().startswith("-")):
                bad.append(f"{f.name}:{no}: {code.strip()}")
    assert not bad, "a shipped compose file publishes on every interface:\n  " + "\n  ".join(bad)


def test_the_guard_sees_each_shape():
    assert BIND.search('      - "${NOO_BIND_ADDR:-0.0.0.0}:${NOO_PORT_GATEWAY:-8080}:8080"').group(1) == ":-0.0.0.0"
    assert BIND.search('      - "${NOO_BIND_ADDR}:4222:4222"').group(1) == ""
    assert BIND.search('      - "${NOO_BIND_ADDR:-127.0.0.1}:9100:9100"').group(1) == ":-127.0.0.1"
    assert OPEN.search('      - "0.0.0.0:8080:8080"')
    assert not OPEN.search('      - "127.0.0.1:${NOO_PORT_GRAFANA:-3000}:3000"')
