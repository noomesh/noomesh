# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Modular capability-pipeline framework.

The model is the intelligence; the harness supplies deterministic capabilities;
tasks are declarative compositions. See core.py. Research is the first composition (research.py);
sandbox capabilities (container-executed manifests) register via
sandbox_capabilities.py.

DISCOVERY MECHANISM (mirrors noomesh.workers.__init__): importing this
package calls :func:`register_capabilities`, which eagerly imports every
built-in capability module so their ``@capability`` decorators populate the
registry as a side effect — a new module can't silently not-register. Adding
a new built-in capability module = write it, decorate, add it to
``_BUILTIN_CAPABILITY_MODULES``. Third-party packages can register via the
``noomesh.capabilities`` entry-points group (each entry point resolves to
a module or callable that registers capabilities on load).

All capability modules must stay cheap to import: heavy/optional deps are
imported lazily inside capability bodies, on purpose.
"""
from .core import (
    Pipeline,
    PipelineResult,
    PipelineValidationError,
    Step,
    capability,
    get_capability,
    registered_capabilities,
    run_pipeline,
    validator,
)

import structlog as _structlog

_log = _structlog.get_logger("pipeline")

# Built-in modules whose import registers capabilities/validators.
_BUILTIN_CAPABILITY_MODULES = (
    "capabilities",
    "research",
    "sandbox_capabilities",
)

_ENTRY_POINT_GROUP = "noomesh.capabilities"

_registered = False


def register_capabilities(force: bool = False) -> list[str]:
    """Eagerly discover and register all capabilities. Idempotent.

    1. Imports each built-in capability module (decorator side effects).
    2. Calls sandbox_capabilities.register_sandbox_capabilities() to fold
       manifest-declared sandbox capabilities into the registry.
    3. Loads any ``noomesh.capabilities`` entry points (module or callable).

    Returns the sorted list of registered capability names.
    """
    global _registered
    if _registered and not force:
        return registered_capabilities()
    import importlib

    for mod in _BUILTIN_CAPABILITY_MODULES:
        try:
            importlib.import_module(f"{__name__}.{mod}")
        except Exception as e:  # noqa: BLE001 — one bad module must not sink the rest
            _log.warning("pipeline.capability_module_failed", module=mod, error=str(e)[:200])

    try:
        from .sandbox_capabilities import register_sandbox_capabilities
        register_sandbox_capabilities()
    except Exception as e:  # noqa: BLE001
        _log.warning("pipeline.sandbox_capabilities_failed", error=str(e)[:200])

    try:
        from importlib.metadata import entry_points
        for ep in entry_points(group=_ENTRY_POINT_GROUP):
            try:
                obj = ep.load()
                if callable(obj):
                    obj()
            except Exception as e:  # noqa: BLE001
                _log.warning("pipeline.entry_point_failed", entry_point=ep.name, error=str(e)[:200])
    except Exception:  # noqa: BLE001 — metadata backend quirks
        pass

    _registered = True
    return registered_capabilities()


# Eager discovery at package import (mirrors workers/__init__).
register_capabilities()

__all__ = [
    "Pipeline",
    "PipelineResult",
    "PipelineValidationError",
    "Step",
    "capability",
    "get_capability",
    "register_capabilities",
    "registered_capabilities",
    "run_pipeline",
    "validator",
]
