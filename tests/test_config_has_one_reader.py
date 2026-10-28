# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""One Python module finds and loads noomesh.yaml: noomesh.config.

kb_roles used to carry its own ("/app/noomesh.yaml", "noomesh.yaml") tuple and
its own yaml.safe_load, so a container started with NOO_CONFIG read
kb.source_roles from a different file than every other setting. Rust finds the
file with the same order (see `config_search_candidates`), so the two cannot
disagree.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from noomesh import config as cfgmod

SRC = Path(__file__).resolve().parents[1] / "src" / "noomesh"
OWNER = SRC / "config.py"

# Other YAML documents, not noomesh.yaml: the trusted-hosts inventory and skill manifests.
OTHER_DOCUMENTS = {"cluster/inventory.py", "skills/skill_manifest.py"}
# Names the file only to REFUSE ingesting it.
NAMES_ONLY_TO_DENY = {"workers/ingest_confine.py"}


def _rel(p: Path) -> str:
    return p.relative_to(SRC).as_posix()


def _py_files() -> list[Path]:
    return sorted(p for p in SRC.rglob("*.py") if p != OWNER)


def test_nothing_outside_config_parses_yaml_or_names_the_file() -> None:
    files = _py_files()
    assert len(files) > 20 and OWNER.exists(), "the scan found nothing: this guard would pass vacuously"
    offenders = []
    for p in files:
        rel = _rel(p)
        tree = ast.parse(p.read_text(encoding="utf-8-sig"), filename=str(p))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"safe_load", "load", "full_load"}
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "yaml"
                and rel not in OTHER_DOCUMENTS
            ):
                offenders.append(f"{rel}:{node.lineno} yaml.{node.func.attr}")
            # Docstrings talk about the file; code that OPENS it names it as a literal.
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value.endswith("noomesh.yaml")
                and " " not in node.value
                and rel not in NAMES_ONLY_TO_DENY
            ):
                offenders.append(f"{rel}:{node.lineno} literal {node.value!r}")
    assert not offenders, "find/load noomesh.yaml through noomesh.config:\n" + "\n".join(offenders)


def test_the_allowlists_are_not_stale() -> None:
    for rel in OTHER_DOCUMENTS | NAMES_ONLY_TO_DENY:
        assert (SRC / rel).exists(), f"{rel} is allowlisted but gone: drop it from the list"


@pytest.fixture
def clean(monkeypatch, tmp_path):
    for v in ("NOO_CONFIG", "NOO_CONFIG_PATH", "NOO_REPO_ROOT", "NOO_HOME"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_search_order_matches_the_rust_cli(clean, monkeypatch) -> None:
    root = clean / "install"
    root.mkdir()
    monkeypatch.setenv("NOO_REPO_ROOT", str(root))
    got = cfgmod.config_search_candidates()
    assert got == [
        clean / "noomesh.yaml",
        Path("/app/noomesh.yaml"),
        root / "noomesh.yaml",
        clean / "home" / ".config" / "mesh" / "config.yaml",
    ]


def test_standalone_home_needs_its_marker(clean, monkeypatch) -> None:
    home = clean / "home" / ".noo"
    home.mkdir(parents=True)
    assert home / "noomesh.yaml" not in cfgmod.config_search_candidates()
    (home / ".noo-standalone").write_text("")
    assert home / "noomesh.yaml" in cfgmod.config_search_candidates()


def test_explicit_beats_search(clean, monkeypatch) -> None:
    (clean / "noomesh.yaml").write_text("kb: {default_roles: [cwd]}\n")
    other = clean / "other.yaml"
    other.write_text("kb: {default_roles: [env]}\n")
    assert cfgmod.read_config_yaml()["kb"]["default_roles"] == ["cwd"]
    monkeypatch.setenv("NOO_CONFIG", str(other))
    assert cfgmod.read_config_yaml()["kb"]["default_roles"] == ["env"]


def test_kb_roles_follows_noo_config(clean, monkeypatch) -> None:
    """The divergence this fixes: kb_roles ignored NOO_CONFIG."""
    from noomesh.gateway import kb_roles

    (clean / "noomesh.yaml").write_text("kb: {default_roles: [cwd]}\n")
    other = clean / "other.yaml"
    other.write_text("kb: {default_roles: [env]}\n")
    monkeypatch.setenv("NOO_CONFIG", str(other))
    monkeypatch.setitem(kb_roles._cache, "loaded_at", 0.0)
    assert kb_roles.default_roles() == ["env"]


def test_no_file_is_an_empty_mapping(clean) -> None:
    assert cfgmod.read_config_yaml() == {}
