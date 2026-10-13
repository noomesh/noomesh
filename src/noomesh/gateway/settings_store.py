# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Persistent user settings store — survives Docker rebuilds.

ℹ️ LIVE PYTHON LIBRARY — NOT a router. Rust ``settings.rs`` handles the
``/api/settings*`` HTTP routes but does not yet read/write this JSON file
directly. This module remains the source of truth for the
``/data/noo-settings.json`` file consumed by the Python lifespan seed
step. Verify Rust counterpart before deprecating; if Rust is the writer,
this becomes a read-only Python compat shim.

Writes a JSON file to the mounted data volume (``/data/noo-settings.json``)
which lives on the host filesystem outside the DB.  On startup the gateway
reads this file and seeds the database so user configuration choices
(task toggles, channel recipients, preferences) are restored even when
the postgres volume is wiped.

Layers:
    1. Starting config    — ``noomesh.yaml`` (repo defaults)
    2. Dynamic DB state   — PostgreSQL tables (runtime, may be lost on rebuild)
    3. **User settings**  — ``noo-settings.json`` (this module, host filesystem)

Layer 3 is authoritative for user intent.  When layer 2 is empty after a
rebuild, layer 3 restores the user's choices on top of layer 1 defaults.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)

_SETTINGS_FILENAME = "noo-settings.json"
_DEFAULT_DATA_DIR = "/data"


def _settings_path() -> Path:
    """Resolve the settings file path.

    Uses ``NOO_SETTINGS_FILE`` env var if set, otherwise
    ``/data/noo-settings.json`` (the ``noo-data`` volume mount).
    """
    explicit = os.getenv("NOO_SETTINGS_FILE")
    if explicit:
        return Path(explicit)
    data_dir = os.getenv("NOO_DATA_DIR", _DEFAULT_DATA_DIR)
    return Path(data_dir) / _SETTINGS_FILENAME


class SettingsStore:
    """File-backed JSON settings store.

    Thread-safe: all writes go through a lock.
    """

    VERSION = 2

    def __init__(self, path: Path | str | None = None) -> None:
        self._path = Path(path) if path else _settings_path()
        self._lock = threading.Lock()
        self._data: dict[str, Any] = self._load()
        log.info("settings_store_initialized", path=str(self._path),
                 exists=self._path.exists())

    # -- Low-level I/O -----------------------------------------------------

    def _load(self) -> dict[str, Any]:
        if not self._path.exists():
            return self._empty()
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                log.warning("settings_store_invalid_format", path=str(self._path))
                return self._empty()
            return data
        except Exception as e:
            log.error("settings_store_load_error", error=str(e))
            return self._empty()

    def _save(self) -> None:
        self._data["version"] = self.VERSION
        self._data["updated_at"] = datetime.now(timezone.utc).isoformat()
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, default=str)
            tmp.replace(self._path)
        except Exception as e:
            log.error("settings_store_save_error", error=str(e))

    @staticmethod
    def _empty() -> dict[str, Any]:
        return {
            "version": SettingsStore.VERSION,
            "updated_at": None,
            "heartbeat_tasks": {},
            "channel_recipients": [],
            "autonomy_locations": {},
            "preferences": {},
        }

    # -- Public: full snapshot --------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Return the full settings dict (read-only copy)."""
        with self._lock:
            return json.loads(json.dumps(self._data, default=str))

    def restore(self, data: dict[str, Any]) -> None:
        """Replace all settings with *data* (import)."""
        with self._lock:
            self._data = data
            self._save()
        log.info("settings_store_restored")

    # -- Heartbeat task overrides -----------------------------------------

    def get_task_overrides(self) -> dict[str, dict[str, Any]]:
        """Return ``{task_id: {enabled, schedule, config, ...}}``."""
        return self._data.get("heartbeat_tasks", {})

    def save_task(self, task_id: str, task_data: dict[str, Any]) -> None:
        """Save a task's user-set state (enabled, schedule, config, channels, recipients)."""
        with self._lock:
            tasks = self._data.setdefault("heartbeat_tasks", {})
            tasks[task_id] = {
                "enabled": task_data.get("enabled", True),
                "schedule": task_data.get("schedule"),
                "config": task_data.get("config", {}),
                "channels": task_data.get("channels", []),
                "recipients": task_data.get("recipients", []),
                "name": task_data.get("name", task_id),
                "action": task_data.get("action", "custom_prompt"),
                "created_by": task_data.get("created_by", "user"),
            }
            self._save()

    def save_task_toggle(self, task_id: str, enabled: bool) -> None:
        """Quick toggle — update only the enabled flag for one task."""
        with self._lock:
            tasks = self._data.setdefault("heartbeat_tasks", {})
            if task_id in tasks:
                tasks[task_id]["enabled"] = enabled
            else:
                tasks[task_id] = {"enabled": enabled}
            self._save()

    def remove_task(self, task_id: str) -> None:
        """Remove a task from settings."""
        with self._lock:
            self._data.get("heartbeat_tasks", {}).pop(task_id, None)
            self._save()

    # -- Channel recipients -----------------------------------------------

    def get_channel_recipients(self) -> list[dict[str, Any]]:
        """Return saved channel recipients."""
        return self._data.get("channel_recipients", [])

    def save_channel_recipient(self, recipient: dict[str, Any]) -> None:
        """Add or update a channel recipient (keyed by channel + recipient_id)."""
        with self._lock:
            recips = self._data.setdefault("channel_recipients", [])
            # Find existing by channel + recipient_id
            key = (recipient.get("channel"), recipient.get("recipient_id"))
            for i, r in enumerate(recips):
                if (r.get("channel"), r.get("recipient_id")) == key:
                    recips[i] = recipient
                    self._save()
                    return
            recips.append(recipient)
            self._save()

    def remove_channel_recipient(self, channel: str, recipient_id: str) -> None:
        """Remove a channel recipient."""
        with self._lock:
            recips = self._data.get("channel_recipients", [])
            self._data["channel_recipients"] = [
                r for r in recips
                if not (r.get("channel") == channel and r.get("recipient_id") == recipient_id)
            ]
            self._save()

    # -- Autonomy locations -----------------------------------------------

    def get_autonomy_overrides(self) -> dict[str, bool]:
        """Return ``{location_name: enabled}`` for user-toggled locations."""
        return self._data.get("autonomy_locations", {})

    def save_autonomy_location(self, name: str, enabled: bool) -> None:
        """Save the enabled state of an autonomy location."""
        with self._lock:
            locs = self._data.setdefault("autonomy_locations", {})
            locs[name] = enabled
            self._save()

    # -- Generic preferences ----------------------------------------------

    def get_preference(self, key: str, default: Any = None) -> Any:
        return self._data.get("preferences", {}).get(key, default)

    def set_preference(self, key: str, value: Any) -> None:
        with self._lock:
            self._data.setdefault("preferences", {})[key] = value
            self._save()


# -- Module singleton ------------------------------------------------------

_store: SettingsStore | None = None


def init_settings_store(path: Path | str | None = None) -> SettingsStore:
    global _store
    _store = SettingsStore(path)
    return _store


def get_settings_store() -> SettingsStore | None:
    return _store
