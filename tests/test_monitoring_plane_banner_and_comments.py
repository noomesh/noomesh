# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""an earlier change and §5: what the operator reads about the monitoring
plane must name what is actually there.

§5 — the rebuild banner printed Grafana at its bind host only. On a tailnet
bind the URL a browser dials is `GRAFANA_ROOT_URL` (the MagicDNS name, the
same value the gateway hands out for SSO), so the banner prints it first,
exactly as it already does for the gateway's `NOO_GATEWAY_URL`. These run
the real `print_service_urls` against a real `.env`, because the launchers
never source it.

§4 — the `postgres-data` volume comment named `~/pai/postgres`; onboard's
`ensure_pg_data_path` writes `$HOME/noo/postgres`.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "scripts" / "lib-bind-addr.sh"


def banner(tmp_path: Path, env_file: str, **shell_env: str) -> str:
    (tmp_path / ".env").write_text(env_file)
    script = f'cd "{tmp_path}"\n. "{LIB}"\nprint_service_urls full\n'
    out = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": "/usr/bin:/bin", **shell_env},
    )
    assert out.returncode == 0, out.stderr
    return out.stdout


def grafana_lines(out: str) -> list[str]:
    return [ln.strip() for ln in out.splitlines() if ln.strip().startswith("Grafana")]


def test_grafana_root_url_from_env_file_is_printed_first(tmp_path: Path) -> None:
    out = banner(tmp_path, "GRAFANA_ROOT_URL=https://host8.tail1234.ts.net:3000\n")
    lines = grafana_lines(out)
    assert lines, out
    assert lines[0] == "Grafana:            https://host8.tail1234.ts.net:3000", lines
    assert lines[1] == "Grafana (local):    https://localhost:3000", lines


def test_grafana_root_url_from_the_environment_wins(tmp_path: Path) -> None:
    out = banner(tmp_path, "GRAFANA_ROOT_URL=https://file.example:3000\n", GRAFANA_ROOT_URL="https://env.example:3000")
    assert grafana_lines(out)[0].endswith("https://env.example:3000"), out


def test_no_root_url_prints_the_bind_host_once(tmp_path: Path) -> None:
    out = banner(tmp_path, "NOO_BIND_MODE=local\n")
    assert grafana_lines(out) == ["Grafana:            https://localhost:3000"], out


def test_root_url_naming_the_bind_host_is_not_printed_twice(tmp_path: Path) -> None:
    out = banner(tmp_path, "GRAFANA_ROOT_URL=https://localhost:3000\n")
    assert grafana_lines(out) == ["Grafana:            https://localhost:3000"], out


def test_postgres_data_comment_names_the_path_onboard_writes() -> None:
    steps = (ROOT / "noo-cli/src/onboard/steps.rs").read_text()
    m = re.search(r'let pg = format!\("\{home\}/([^"]+)"\);', steps)
    assert m, "ensure_pg_data_path no longer builds the WSL2 path from {home}; update this guard"
    compose = (ROOT / "docker-compose.cluster.yml").read_text()
    block = compose.split("\n  postgres-data:\n", 1)[1].split("\n  claude-config:", 1)[0]
    assert f"$HOME/{m.group(1)}" in block, f"the postgres-data comment must name $HOME/{m.group(1)}:\n{block}"
    assert "~/pai/postgres" not in block
