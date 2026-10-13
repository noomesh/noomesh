# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""An add-on declares its worker handlers; the mesh does not name them.

`workers/__init__.py` imports a tuple of module names this repo maintains.
That is why moving `temporal_graph` and `temporal_extractor` into the
trellion-intel add-on's package broke `graph.py` from another repo, silently —
the mesh knows add-on module names, so an add-on cannot move its own code
without breaking a caller it cannot see.

An installed package may now declare handlers in the
`noomesh.worker_surfaces` entry-point group instead, the way a third-party
capability already registers through `noomesh.capabilities`.
"""

from __future__ import annotations

import types

import pytest

from noomesh import workers


class _EP:
    """Minimal stand-in for an importlib.metadata EntryPoint."""

    def __init__(self, name: str, obj):
        self.name = name
        self._obj = obj

    def load(self):
        if isinstance(self._obj, Exception):
            raise self._obj
        return self._obj


@pytest.fixture
def declared(monkeypatch):
    """Publish fake entry points into the group."""

    def _set(*eps: _EP):
        import importlib.metadata as md

        monkeypatch.setattr(md, "entry_points", lambda group=None: list(eps))

    return _set


def test_a_declared_surface_is_loaded(declared):
    called = {"n": 0}

    def register():
        called["n"] += 1

    declared(_EP("ml:fake", register))
    loaded = workers._load_declared_surfaces("ml")
    assert loaded == ["ml:fake"]
    assert called["n"] == 1


def test_a_module_entry_point_needs_no_callable(declared):
    """Importing the module is what registers, exactly as the built-ins do."""
    declared(_EP("ml:fake", types.ModuleType("fake_surface")))
    assert workers._load_declared_surfaces("ml") == ["ml:fake"]


def test_the_surface_gate_still_applies(declared):
    """trellion and trellion-intel ship in the same image. A licensed surface
    must not register on the core worker just because the package is there."""
    declared(_EP("ml-intel:graph", lambda: None))
    assert workers._load_declared_surfaces("core") == []
    assert workers._load_declared_surfaces("ml-intel") == ["ml-intel:graph"]


def test_all_takes_everything(declared):
    declared(_EP("ml-intel:graph", lambda: None), _EP("core:thing", lambda: None))
    assert len(workers._load_declared_surfaces("all")) == 2


def test_an_unprefixed_name_is_treated_as_all(declared):
    declared(_EP("legacy", lambda: None))
    assert workers._load_declared_surfaces("core") == ["legacy"]


def test_a_broken_declaration_warns_and_does_not_take_the_worker_down(declared):
    """The failure this followup exists to end. The memory shim's
    `except ImportError: pass` made a broken add-on look like an absent one,
    and the add-on's modules were unreachable for a release."""
    declared(_EP("ml:broken", ImportError("no module named 'x'")))
    with pytest.warns(UserWarning, match="ml:broken"):
        loaded = workers._load_declared_surfaces("ml")
    assert loaded == []


def test_one_broken_declaration_does_not_block_the_others(declared):
    declared(_EP("ml:broken", ImportError("boom")), _EP("ml:fine", lambda: None))
    with pytest.warns(UserWarning):
        loaded = workers._load_declared_surfaces("ml")
    assert loaded == ["ml:fine"]


def test_no_declarations_is_silent_and_normal():
    """Nothing declares yet. An install with no add-on packages must not warn."""
    assert workers._load_declared_surfaces("core") == []


def test_the_group_name_is_namespaced():
    assert workers._ENTRY_POINT_GROUP == "noomesh.worker_surfaces"


def test_the_builtin_import_list_still_works():
    """Declaration is additive. The modules this repo ships keep registering
    the way they always did."""
    assert "worker.tool.generic" in workers.all_handlers()


def test_the_intel_container_warns_when_no_intel_surface_is_declared(declared):
    """The live bug: a copy-installed trellion_intel has no metadata, so its
    surfaces were never registered and nothing said so."""
    declared(_EP("core:thing", lambda: None))
    with pytest.warns(UserWarning, match="ml-intel.*NOT served"):
        assert workers._load_declared_surfaces("ml-intel") == []


def test_the_intel_container_is_quiet_when_its_surfaces_are_declared(declared, recwarn):
    declared(_EP("ml-intel:retrieval", lambda: None))
    assert workers._load_declared_surfaces("ml-intel") == ["ml-intel:retrieval"]
    assert not [w for w in recwarn if "NOT served" in str(w.message)]


def test_other_surfaces_do_not_expect_intel(declared, recwarn):
    declared()
    for surface in ("core", "ml", "all"):
        assert workers._load_declared_surfaces(surface) == []
    assert not [w for w in recwarn if "NOT served" in str(w.message)]


def test_the_intel_image_installs_the_package_with_its_metadata():
    """The image must carry trellion_intel's entry points, so it is pip-installed
    (no deps), never copied; and the build fails if the surfaces are missing."""
    from pathlib import Path

    found = sorted((Path(__file__).resolve().parents[1] / "docker").glob("Dockerfile.*intel"))
    path = found[0] if found else None
    if path is None:
        pytest.skip("the intel image recipe is not part of this tree (public core)")
    df = path.read_text()
    run = [l for l in df.splitlines() if not l.lstrip().startswith("#")]
    body = "\n".join(run)
    assert "pip install --no-deps" in body
    assert 'cp -r /tmp/trellion_intel "$SP/trellion_intel"' not in body
    assert "noomesh.worker_surfaces" in body and "ml-intel:retrieval" in body
