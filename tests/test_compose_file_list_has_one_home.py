# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The compose file list has ONE home: scripts/lib-compose.sh.

an earlier change. Eight scripts used to build COMPOSE_FILES by hand and no
two agreed. start.sh composed the GPU overlay; restart.sh never did, so a
`restart --force` recreated ollama-embed without its GPU reservation. stop,
clean and logs never composed the evolve overlay, so `down --remove-orphans`
removed noo-evolve as an orphan of its own stack. restart put dist before
evolve; start put it after. Each copy was correct about the thing its author
was looking at and wrong about the rest — the same drift #247 closed for
profiles, now closed for files.

Two kinds of assertion, on purpose (see test_launcher_addon_profiles_parity):
SHAPE ones read the scripts, because "calls the shared helper" is the only
property a hand-mirrored copy cannot fake; BEHAVIOUR ones run the helper in a
scratch install, because a helper that exists but orders the files wrong
would pass every shape check.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
HOME = "lib-compose.sh"
# Scripts that compose something OTHER than this install's stack: the
# rotation rehearsal stages its own compose.yml under a scratch project.
NOT_THIS_INSTALL = {"test-rotation-rehearsal.sh"}
# Helpers that run compose with the CALLER's $COMPOSE_FILES, never their
# own: re-deriving the list here would be the second home this file forbids.
# lib-bind-sources.sh renders the exact config the launcher's next `up` uses.
CALLERS_LIST = {"lib-bind-sources.sh"}

# A `docker compose … -f <literal docker-compose.*.yml>` on a live line.
HAND_PICKED = re.compile(r"docker compose\b[^\n]*\s-f\s+\"?\$?\{?[^ \"$]*docker-compose\.")


def _live_lines(path: Path):
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("echo "):
            continue
        yield n, line


@pytest.mark.parametrize("script", sorted(p.name for p in SCRIPTS.glob("*.sh")))
def test_no_script_composes_from_a_hand_picked_file(script: str) -> None:
    if script == HOME or script in NOT_THIS_INSTALL:
        return
    hits = [(n, l.strip()) for n, l in _live_lines(SCRIPTS / script) if HAND_PICKED.search(l)]
    assert not hits, (
        f"{script} composes from a hand-picked file: {hits} — the list has one "
        f"home, scripts/{HOME}::compose_file_args; ask it"
    )


def _compose_consumers() -> list[str]:
    out = []
    for p in sorted(SCRIPTS.glob("*.sh")):
        if p.name == HOME or p.name in NOT_THIS_INSTALL or p.name in CALLERS_LIST:
            continue
        body = p.read_text(encoding="utf-8")
        if re.search(r"docker compose\b[^\n]*COMPOSE_FILES", body) or re.search(
            r"docker compose\b[^\n]*compose_file_args", body
        ):
            out.append(p.name)
    return out


def test_the_consumer_list_was_found() -> None:
    got = _compose_consumers()
    assert {"noomesh-start.sh", "noomesh-restart.sh", "noomesh-stop.sh"} <= set(got), (
        f"the consumer scan no longer finds the launchers ({got}) — the scan broke, "
        "and the guard below would be vacuous"
    )


@pytest.mark.parametrize("script", _compose_consumers())
def test_every_compose_consumer_sources_the_one_home(script: str) -> None:
    body = (SCRIPTS / script).read_text(encoding="utf-8")
    assert re.search(rf"(?:^|[\s;&(])(?:source|\.)\s+[^\n]*{re.escape(HOME)}", body, re.M), (
        f"{script} runs docker compose with a file list but never sources {HOME}"
    )
    assert "COMPOSE_FILES=\"-f" not in body and "COMPOSE_FILES=(-f" not in body, (
        f"{script} still seeds COMPOSE_FILES with a literal — one home"
    )


def test_the_cli_takes_its_list_from_the_same_home() -> None:
    """The onboard wizard is a sanctioned launcher; its compose calls must
    compose the same files as `noo stack start` or it recreates a different
    stack."""
    body = (ROOT / "noo-cli/src/onboard/sh.rs").read_text(encoding="utf-8")
    assert "lib-compose.sh" in body and "compose_file_list" in body, (
        "noo-cli/src/onboard/sh.rs must ask scripts/lib-compose.sh::compose_file_list"
    )


def test_the_helper_ships_with_a_standalone_install() -> None:
    """Every launcher sources it, so a standalone slice without it cannot
    start (the lib-ui.sh lesson, host8 2026-09-03)."""
    for f in ("noo-cli/build.rs", "noo-cli/src/onboard/standalone.rs"):
        assert f'"scripts/{HOME}"' in (ROOT / f).read_text(encoding="utf-8"), f"{f} does not ship {HOME}"


# ── behaviour ──────────────────────────────────────────────────────────────

ALL_FILES = (
    "docker-compose.cluster.yml",
    "docker-compose.gpu-embed.yml",
    "docker-compose.override.yml",
    "docker-compose.trellion.yml",
    "docker-compose.evolve.yml",
    "docker-compose.dist.yml",
)


@pytest.fixture
def install(tmp_path: Path):
    """A scratch install with the REAL helpers and empty compose files."""
    (tmp_path / "scripts").mkdir()
    for lib in ("lib-compose.sh", "lib-addons.sh", "lib-dist.sh"):
        shutil.copy(SCRIPTS / lib, tmp_path / "scripts" / lib)

    def make(*, files=ALL_FILES, evolve: bool | None = None, trellion: bool | None = None, gpu: str = "0", dist: bool = False) -> list[str]:
        for f in files:
            (tmp_path / f).write_text("services: {}\n")
        decl = {k: v for k, v in (("evolve", evolve), ("trellion", trellion)) if v is not None}
        if decl:
            (tmp_path / "noomesh.yaml").write_text(
                "addons:\n" + "".join(f"  {k}: {'true' if v else 'false'}\n" for k, v in decl.items())
            )
        env = {"PATH": "/usr/bin:/bin", "NOO_COMPOSE_GPU": gpu}
        pre = "DIST_MODE=1; DIST_COMPOSE_FILE=docker-compose.dist.yml; " if dist else ""
        out = subprocess.run(
            ["bash", "-c", f". scripts/lib-compose.sh && {pre}compose_file_list ."],
            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30,
        )
        assert out.returncode == 0, out.stderr
        names = [Path(l).name for l in out.stdout.splitlines() if l.strip()]
        assert names, "the helper printed nothing — a silent helper composes nothing"
        return names

    return make


def test_merge_order_is_base_gpu_override_addons_dist(install) -> None:
    """Load-bearing: later files win. dist LAST so pinned image refs beat
    the dev overlay's build: blocks; add-on overlays after the override so a
    site override cannot silently redefine an add-on's service."""
    assert install(evolve=True, gpu="1", dist=True) == list(ALL_FILES)


def test_gpu_overlay_follows_the_probe_not_the_file(install) -> None:
    assert "docker-compose.gpu-embed.yml" not in install(gpu="0"), (
        "a present gpu-embed overlay must NOT be composed on a box with no visible GPU"
    )
    assert "docker-compose.gpu-embed.yml" in install(gpu="1")


def test_an_addon_overlay_follows_the_declaration_not_the_file(install) -> None:
    """The file is shipped with every install; PRESENCE of the file is not
    the switch (yet — phase B makes it so). The declaration is."""
    assert "docker-compose.evolve.yml" not in install(evolve=None), "undeclared: evolve is opt-in"
    assert "docker-compose.evolve.yml" not in install(evolve=False)
    assert "docker-compose.evolve.yml" in install(evolve=True)


def test_an_opt_out_addon_is_composed_unless_declared_off(install) -> None:
    """trellion is the one opt-OUT add-on: its overlay
    is composed with no declaration, and only `trellion: false` removes it."""
    assert "docker-compose.trellion.yml" in install()
    assert "docker-compose.trellion.yml" in install(trellion=True)
    assert "docker-compose.trellion.yml" not in install(trellion=False)


def test_dist_is_composed_only_when_the_caller_resolved_it(install) -> None:
    got = install(dist=False)
    assert "docker-compose.dist.yml" not in got, (
        "a present dist overlay must not be composed on a dev install — DIST_MODE "
        "is lib-dist's verdict, not the file's presence"
    )
    assert install(dist=True)[-1] == "docker-compose.dist.yml"


def test_absent_files_are_not_named(install) -> None:
    assert install(files=("docker-compose.cluster.yml",), gpu="1") == ["docker-compose.cluster.yml"]
