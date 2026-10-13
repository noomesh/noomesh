# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""noomesh asks for add-on capabilities by ROLE; it never names an add-on.

Every external call is proven absent / failing / ok: no add-on, an add-on that
declares nothing for the role or whose declaration does not resolve, and one
that fills it.
"""
from __future__ import annotations

import sys
import types

import pytest

import noomesh.addon_roles as roles


def _pkg(monkeypatch, name, **attrs):
    mod = types.ModuleType(name)
    mod.__dict__.update(attrs)
    monkeypatch.setitem(sys.modules, name, mod)
    return mod


@pytest.fixture(autouse=True)
def _no_ambient_packages(monkeypatch):
    monkeypatch.delenv(roles.ENV_PACKAGES, raising=False)
    monkeypatch.setattr(roles, "_declared_packages", lambda: [p for p in roles.os.getenv(roles.ENV_PACKAGES, "").split(",") if p.strip()])


# -- extensions: ABSENT -------------------------------------------------------

def test_no_declaring_package_yields_nothing():
    assert roles.extensions(roles.CLI_GROUPS) == []


def test_a_named_package_that_is_not_installed_is_skipped_silently(monkeypatch, capsys):
    monkeypatch.setenv(roles.ENV_PACKAGES, "no_such_addon_package_xyz")
    assert roles.extensions(roles.CLI_GROUPS) == []
    assert "extension" not in capsys.readouterr().out


# -- extensions: OK -----------------------------------------------------------

def test_a_declared_extension_resolves_by_module_attr_and_by_module(monkeypatch):
    sub = _pkg(monkeypatch, "fake_ext_pkg.defs")
    _pkg(monkeypatch, "fake_ext_pkg", NOOMESH_EXTENSIONS={
        roles.CLI_GROUPS: {"grp": "fake_ext_pkg.defs:APP"},
        roles.MCP_TOOL_DEFS: {"tools": "fake_ext_pkg.defs:"},
    })
    sub.APP = object()
    monkeypatch.setenv(roles.ENV_PACKAGES, "fake_ext_pkg")
    assert roles.extensions(roles.CLI_GROUPS) == [("grp", sub.APP)]
    assert roles.extensions(roles.MCP_TOOL_DEFS) == [("tools", sub)]
    assert roles.extensions("some_other_kind") == []


# -- extensions: FAILING ------------------------------------------------------

def test_an_unresolvable_declaration_is_skipped_and_logged(monkeypatch):
    seen = []
    monkeypatch.setattr(roles.log, "warning", lambda event, **kw: seen.append((event, kw)))
    _pkg(monkeypatch, "fake_ext_broken", NOOMESH_EXTENSIONS={
        roles.CLI_GROUPS: {"grp": "fake_ext_broken.missing:APP", "ok": "fake_ext_broken:NOOMESH_EXTENSIONS"}})
    monkeypatch.setenv(roles.ENV_PACKAGES, "fake_ext_broken")
    got = roles.extensions(roles.CLI_GROUPS)
    assert [n for n, _ in got] == ["ok"]
    assert [e for e, _ in seen] == ["addon.extension_failed"] and seen[0][1]["name"] == "grp"


def test_a_package_without_a_declaration_contributes_nothing(monkeypatch):
    _pkg(monkeypatch, "fake_ext_plain")
    monkeypatch.setenv(roles.ENV_PACKAGES, "fake_ext_plain")
    assert roles.extensions(roles.CLI_GROUPS) == []


# -- provider -----------------------------------------------------------------

def test_provider_is_trellions_lookup(monkeypatch):
    seam = types.ModuleType("trellion.live._intel")
    seam.addon_provider = lambda role: ("filled", role)
    monkeypatch.setitem(sys.modules, "trellion.live._intel", seam)
    assert roles.provider(roles.GRAPH_RANKER) == ("filled", "graph_ranker")


def test_provider_with_nothing_installed_raises_import_error(monkeypatch):
    seam = types.ModuleType("trellion.live._intel")

    def addon_provider(role):
        raise ImportError(f"{role}: requires the Intelligent tier")

    seam.addon_provider = addon_provider
    monkeypatch.setitem(sys.modules, "trellion.live._intel", seam)
    with pytest.raises(ImportError):
        roles.provider(roles.TEMPORAL_GRAPH_STORE)


def test_shared_role_names_are_trellions():
    intel = pytest.importorskip("trellion.live._intel")
    if not hasattr(intel, "GRAPH_RANKER"):
        pytest.skip("trellion without provider roles")
    assert (roles.GRAPH_RANKER, roles.GRAPH_METRICS) == (intel.GRAPH_RANKER, intel.GRAPH_METRICS)


def test_role_names_are_distinct():
    names = [getattr(roles, n) for n in dir(roles) if n.isupper() and isinstance(getattr(roles, n), str)
             and n not in {"ENTRY_POINT_GROUP", "ENV_PACKAGES", "EXTENSIONS_ATTR"}]
    assert len(names) == len(set(names))
