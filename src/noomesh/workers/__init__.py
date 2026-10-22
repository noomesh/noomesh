# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""NATS ``worker.*`` handler package.

Split out of the former 7,400-line ``noomesh.gateway.worker_pool``
(2026-07-14): one module per domain, each registering its handlers via
``@worker_handler`` from :mod:`noomesh.workers.registry`.

DISCOVERY MECHANISM: importing this package imports every domain module
below, whose decorators populate the registry as a side effect. The
dispatch shell (``noomesh.gateway.worker_pool``) imports this package
and subscribes one NATS subscription per registered subject. Adding a
new handler = write the function in the right domain module (or a new
one), decorate it, and — only if it is a *new* module — add it to the
import list here.

An ADD-ON does not edit that list. It declares its handlers in the
``noomesh.worker_surfaces`` entry-point group, named ``<surface>:<label>``
so the surface gate still applies, and they register when the package is
installed and that surface is selected. See the design — the list above
is why an add-on could not move its own code without breaking callers in
this repo.

All modules must stay cheap to import: heavy/optional dependencies
(trellion, sqlalchemy, httpx, ML stacks, gateway.deps which pulls
FastAPI) are imported lazily inside handler bodies, on purpose.

Reference implementations of handlers whose subjects were ported to native
Rust live in ``legacy/python-workers-reference/`` (2026-08-08 sweep) — they
are NOT importable from here. Everything below either registers a live
subject or is a helper a live path still calls.
"""

from . import registry  # noqa: F401  (re-exported for convenience)

# Import order note: common/kb/rag/recall are imported by other domain
# modules; plain imports here just ensure the whole set loads.
# (`security` was deleted 2026-08-09: worker.security.pki_rotate went
# native — the Rust gateway writes the watcher spool directly.)
# ── Surface selection ─────────────────────────
# NOO_WORKER_SURFACES picks which handler sets IMPORTING THIS PACKAGE
# registers:
#   all  (default) — today's behavior, byte-identical: every module.
#   core — the three non-ML surfaces (tool.generic, coding history, the
#          heartbeat dispatch shell) + registration-free helper modules.
#          This is what the future slim noo-worker container runs.
#   ml   — the trellion knowledge pack (rag/memory/recall/
#          snapshots/autonomy.check_rag). What the opt-in noo-trellion
#          container runs.
#   ml-intel — the Intelligent tier's subjects (temporal extraction + the
#          ML heartbeat action shell). What the opt-in trellion-intel
#          container runs.
# Unknown values fail safe to "all" with a warning — a typo must not
# silently strip capabilities (same rule as NOO_MIGRATIONS_ENVS).
#
# NOTE: this gates only the import-time @worker_handler REGISTRATIONS.
# Direct submodule imports (e.g. worker_pool's `from ..workers.kb
# import _TEAM_NAME_RE`) are unaffected — kb/users register no
# subjects and stay cheap to import by design. (workers/cluster.py, which
# registered nothing and had no caller, was removed 2026-10-22.)
import os as _os
import warnings as _warnings

_CORE_MODULES = ("common", "heartbeat", "kb", "misc", "tools", "users")
_ML_MODULES = ("autonomy", "memory", "rag", "snapshots", "recall")
# The Intelligent tier's surface: graph
# (worker.temporal.extract) and heartbeat_ml (worker.api.heartbeat.run_ml,
# the TRELLION_ACTIONS shell) touch only the graph-engine modules,
# so they run on the trellion-intel container (NOO_WORKER_SURFACES=ml-intel),
# gated by `addons.trellion_intel: true` in noomesh.yaml on the gateway
# side (there is no per-add-on env flag any more — gateway-rust/src/addons.rs).
_ML_INTEL_MODULES = ("graph", "heartbeat_ml")

_surfaces = (_os.getenv("NOO_WORKER_SURFACES") or "all").strip().lower()
if _surfaces not in ("all", "core", "ml", "ml-intel"):
    _warnings.warn(
        f"unknown NOO_WORKER_SURFACES={_surfaces!r} — falling back to 'all' "
        "(valid: all, core, ml, ml-intel)",
        stacklevel=2,
    )
    _surfaces = "all"

import importlib as _importlib

_selected = {
    "all": _CORE_MODULES + _ML_MODULES + _ML_INTEL_MODULES,
    "core": _CORE_MODULES,
    "ml": _ML_MODULES + ("common", "kb"),  # ML handlers import both
    "ml-intel": _ML_INTEL_MODULES + ("common", "kb"),
}[_surfaces]
for _m in _selected:
    _importlib.import_module(f".{_m}", __name__)

# ── Add-on surfaces ──────────────────────────────────
#
# Everything above is a module this repo ships, named in a tuple this repo
# maintains. That is why moving `temporal_graph` and `temporal_extractor`
# into the trellion-intel add-on's package broke `graph.py` from another repo,
# silently: the mesh knows add-on module names, so an add-on cannot move
# its own code.
#
# An installed package may instead DECLARE its handlers, the way a
# third-party capability already registers through `noomesh.capabilities`
# (`noomesh/pipeline/__init__.py`). Each entry point resolves to a module
# whose import registers `@worker_handler` subjects, or to a callable that
# registers them. Nothing here names the package.
#
# Surface gating still applies, and it is the ENTRY POINT NAME that carries
# it: `<surface>:<label>`, e.g. `ml-intel:graph`. An add-on that ships a
# licensed surface must not have it registered on the core worker just
# because the package happens to be installed in the same image — which it
# is, for trellion and trellion-intel. A name with no surface prefix is
# treated as `all`.
_ENTRY_POINT_GROUP = "noomesh.worker_surfaces"


def _load_declared_surfaces(surface: str) -> "list[str]":
    """Import every entry point whose surface matches. Returns what loaded."""
    loaded: list[str] = []
    try:
        from importlib.metadata import entry_points

        eps = list(entry_points(group=_ENTRY_POINT_GROUP))
    except Exception:  # noqa: BLE001 — metadata backends differ across runtimes
        return loaded

    for _ep in eps:
        _want, _sep, _ = _ep.name.partition(":")
        if not _sep:
            # No prefix at all: the declaration names no surface, so it runs
            # everywhere. `partition` returns the WHOLE string as the head
            # when the separator is absent, so this test is on the separator
            # and not on the head — otherwise `legacy` reads as a surface
            # called "legacy" and matches nothing.
            _want = "all"
        if _want != "all" and surface != "all" and _want != surface:
            continue
        try:
            _obj = _ep.load()
            if callable(_obj):
                _obj()
            loaded.append(_ep.name)
        except Exception as e:  # noqa: BLE001
            # LOUD. A declared surface that will not load is the failure this
            # followup exists to end — the shim's `except ImportError: pass`
            # is what hid fifteen unreachable modules for a release. A broken
            # add-on must not look like an absent one.
            _warnings.warn(
                f"worker surface {_ep.name!r} declared by an installed package "
                f"failed to load: {e}. Its subjects are NOT served.",
                stacklevel=2,
            )

    # The trellion-intel container (NOO_WORKER_SURFACES=ml-intel) declares the
    # trellion-intel add-on, and that package's own surfaces arrive ONLY through
    # this group. An image that copied the package into site-packages without
    # its metadata has no entry points at all, and nothing above complains:
    # the subjects are simply never registered (worker.graph.console_piece and
    # worker.retrieval.feedback, until the Dockerfile installed it with pip).
    # Absent must not look like fine.
    if surface == "ml-intel" and not any(
        ep.name.partition(":")[0] == "ml-intel" for ep in eps
    ):
        _warnings.warn(
            "NOO_WORKER_SURFACES=ml-intel but no installed package declares an "
            f"'ml-intel:' entry point in {_ENTRY_POINT_GROUP!r}: the Intelligent "
            "tier's own surfaces are NOT served. Install trellion_intel with its "
            "metadata (pip install --no-deps), not by copying the package.",
            stacklevel=2,
        )
    return loaded


_DECLARED = _load_declared_surfaces(_surfaces)

from .registry import all_handlers, get_handler, worker_handler  # noqa: F401,E402
