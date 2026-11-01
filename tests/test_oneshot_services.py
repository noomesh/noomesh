# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Declared one-shot compose services (noomesh-internal i64a, operator
decision 2026-10-31).

`noo stack status` FAILs on an Exited container unless its service is on
`config/oneshot-services.txt` and it exited 0; the roll summary counts a bare
`Exited` as done only for a service on the list. So a new one-shot that is not
declared would turn every healthy status red, and a long-running service
wrongly declared would hide a crash. This guard keeps the list and the compose
files in step:

* every service with `restart: "no"` in a root docker-compose*.yml is on the
  list, or is named below as long-running with the reason (`restart: "no"`
  alone does not make a one-shot: `browser` is on-demand and long-running,
  so its exit IS a failure). A new one is a decision either way;
* every list entry is either such a service or a documented add-on one-shot
  (an add-on's overlay lives in its own repository);
* the list ships: build.rs embeds it for an installed box with no checkout.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
LIST = ROOT / "config" / "oneshot-services.txt"

# One-shots declared by an add-on's own overlay, not by this repository's
# compose files. Each must say so on its line.
ADDON_ONESHOTS = {"noo-evolve-routes"}

# `restart: "no"` services that run until stopped: an exit of one is a real
# failure, so they are deliberately NOT on the list.
LONG_RUNNING_RESTART_NO = {
    "browser": "Playwright, started on demand and left running; `noo browser stop` ends sessions, not the container",
}


def _listed() -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in LIST.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, _, why = line.partition(" ")
        out[name] = why.strip()
    return out


def _restart_no() -> set[str]:
    names: set[str] = set()
    files = sorted(ROOT.glob("docker-compose*.yml"))
    assert files, "no compose files found: the guard would pass on nothing"
    for f in files:
        doc = yaml.safe_load(f.read_text()) or {}
        for svc, spec in (doc.get("services") or {}).items():
            if str((spec or {}).get("restart", "")).strip() == "no":
                names.add(svc)
    return names


def test_every_run_once_compose_service_is_declared() -> None:
    restart_no = _restart_no()
    assert restart_no, "found no restart: \"no\" service: the parse found nothing"
    missing = restart_no - set(_listed()) - set(LONG_RUNNING_RESTART_NO)
    assert not missing, (
        f"run-once services not in config/oneshot-services.txt: {sorted(missing)} — "
        "`noo stack status` would FAIL on them once they exit; declare each (i64a)"
    )


def test_every_declared_one_shot_exists_and_says_what_it_does() -> None:
    listed = _listed()
    assert "noo-evolve-routes" in listed, "the known add-on one-shot is declared"
    restart_no = _restart_no()
    for name, why in listed.items():
        assert why, f"{name}: say what it does"
        assert name in restart_no or name in ADDON_ONESHOTS, (
            f"{name} is declared a one-shot but no root compose file runs it once and it is not "
            "a known add-on one-shot: a long-running service on this list would hide its crash"
        )


def test_a_long_running_exception_is_still_a_restart_no_service_and_not_on_the_list() -> None:
    restart_no, listed = _restart_no(), _listed()
    for name, why in LONG_RUNNING_RESTART_NO.items():
        assert name in restart_no, f"{name}: no longer restart: \"no\"; drop the exception"
        assert name not in listed, f"{name} is long-running: declaring it a one-shot would hide its crash"
        assert why


def test_the_list_ships_with_the_cli() -> None:
    build = (ROOT / "noo-cli" / "build.rs").read_text()
    assert '"config/oneshot-services.txt",' in build, "an installed box has no checkout: embed the list"
