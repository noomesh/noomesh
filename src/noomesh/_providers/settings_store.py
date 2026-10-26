# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Settings store provider — user-mutable runtime config.

Replaces direct imports of:
    from noomesh.gateway.settings_store import get_settings_store

Consumers:
    - (former channels/router.py sites; module deleted, history: git log before 2026-08-08)

Why: settings storage location (currently ``/data/noo-settings.json``)
is MESH infrastructure. HARNESS reads/writes user prefs without needing
to know where they're persisted.
"""

from __future__ import annotations

from typing import Any, Optional, Protocol, runtime_checkable


@runtime_checkable
class SettingsStoreProvider(Protocol):
    """Provider for runtime user-settings access.

    The returned ``store`` (if any) exposes whatever the live
    ``gateway.settings_store.SettingsStore`` exposes — get/set/all etc.
    Callers should program against duck-typed access (`store.get(key)`,
    `store.set(key, value)`) rather than introspecting the type.
    """

    def store(self) -> Optional[Any]:
        """Return the live SettingsStore singleton, or None if not
        initialised (e.g., gateway lifespan hasn't run yet)."""
        ...


class GatewaySettingsStoreProvider:
    """Default impl that delegates to ``gateway.settings_store``."""

    def store(self) -> Optional[Any]:
        try:
            from ..gateway.settings_store import get_settings_store
            return get_settings_store()
        except Exception:
            return None


def default_settings_store() -> SettingsStoreProvider:
    return GatewaySettingsStoreProvider()
