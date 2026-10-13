# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The memory shim serves trellion.live only; add-on capabilities are asked for by role.

The shim used to search a list of provider packages, one of them the licensed
add-on, so a caller could say `noomesh.memory.<add-on module>`. That put an
add-on's module names in the open tree. Add-on capabilities are now reached
through `noomesh.addon_roles` (a role name, the add-on declares what fills
it), and this shim advertises only what trellion.live supplies.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

from noomesh import memory as shim


def test_the_shim_serves_trellion_live_only(monkeypatch):
    made = types.ModuleType("trellion.live.only_here")
    monkeypatch.setitem(sys.modules, "trellion.live.only_here", made)
    assert shim._resolve_submodule("only_here") is made


def test_a_name_nobody_supplies_resolves_to_none():
    assert shim._resolve_submodule("nowhere_mod_at_all") is None


def test_no_other_package_is_consulted():
    """A module that exists only OUTSIDE trellion.live must not be served."""
    src = Path(shim.__file__).read_text()
    assert "_PROVIDERS" not in src
    assert "find_spec" not in src


def test_unresolved_names_are_reported_not_swallowed():
    src = Path(shim.__file__).read_text()
    assert "memory.submodules_unresolved" in src
    assert "except ImportError:\n        # Optional submodule" not in src


def test_embedding_client_is_not_advertised():
    assert "embedding_client" not in shim._SUBMODULES


def test_the_shim_advertises_no_addon_module():
    """The advertised names are the open tier's. A graph-engine module here would
    be an add-on module name in the public tree again."""
    advertised = set(shim._SUBMODULES)
    assert not {n for n in advertised if n.startswith(("graph_n", "graph_g", "graph_s", "retrieval_", "temporal_", "intelligent_"))}
