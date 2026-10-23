# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Admin-toggnable behavioral feature flags: DB override → env → default.

The ``REGISTRY`` is the source of truth for which BEHAVIORAL flags exist, their
defaults, and their UI grouping. ``flag(key)`` / ``get_setting(key)`` resolve in
order: a ``noo_settings`` row (admin override) → the env var → the registered
default. An empty table therefore changes nothing — env stays the bootstrap
default. Values are cached with a short TTL so a UI toggle propagates within
seconds without a restart or a DB hit per read.

This is deliberately SYNC (a drop-in for ``os.environ.get`` at existing read
sites). Security-posture gates (multi-user, auth, TLS) are NOT here — they are
operator-managed via ``noo_security_posture`` and never weakenable from the app.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass

_TRUTHY = {"1", "true", "yes", "on"}
_CACHE_TTL = 15.0  # seconds — UI toggles take effect within this window


@dataclass(frozen=True)
class FlagSpec:
    key: str
    category: str
    default: bool
    label: str
    help: str


# Behavioral flags exposed for admin toggling. Grouped by `category` for the UI.
# `default` = the code default when neither the DB nor env sets it. The autonomy
# gates default OFF (Phase-1 behavior; matches env_on in agent_meta_loop.rs).
# Deploy-time flags (NOO_PRO_ENABLED) are NOT here — they gate what the
# launcher deploys, not gateway runtime, so a DB toggle would be inert.
# NOO_EVOLVE_HOFSTADTER_ENABLED *is* registered: the Rust pro routes resolve
# it DB-row-first at runtime (routes/pro.rs), so the toggle is live.
# Keep in sync with gateway-rust/src/routes/settings.rs::FLAG_REGISTRY.
_FLAGS = [
    # ── Autonomy ──
    #
    # The nine NOO_AGENT_* gates and NOO_SELF_DEVELOP_AUTO_RESTART are GONE
    # (2026-09-04): the agent meta-loop moved to the evolve add-on, which reads
    # them from its own container env. A row here would be a switch on another
    # process's behaviour that nothing in this one can honour. Three of them
    # never had a reader anywhere and rendered as working
    # dashboard toggles, which is why they are deleted rather than relocated.
    # NOO_SELF_MODIFY_ENABLED (category "selfdev") is gone: the state-changing
    # self-admin MCP tools were removed, so the model cannot restart or rebuild
    # its own stack and the flag had nothing left to switch. The HTTP endpoints
    # it gated are Admin-role gated now (see routes/admin.rs).
    # ── Features (Python) ──
    FlagSpec("CLOUD_PROVIDERS_ENABLED", "features", False,
             "Cloud model routing", "Allow routing to cloud models (claude-* etc.)."),
    FlagSpec("NOO_EVOLVE_HOFSTADTER_ENABLED", "features", True,
             "Evolve loop", "Enable the evolve add-on's self-reflection loop."),
    # ── Kiosk (Rust-read) ──
    # Read only by the gateway (routes/kiosk.rs::graph_labels_on), from the
    # noo_settings row alone: no env layer, so the retired
    # NOO_KIOSK_GRAPH_LABELS cannot stand in for it. Listed for parity.
    FlagSpec("kiosk.graph_labels", "kiosk", False,
             "Kiosk graph labels",
             "Show entity names and relation types on the kiosk display's knowledge graph."),
    # ── At rest (Rust-read) ──
    # The recorded opt-out of encrypting this controller's data at rest
    # (i10a). DB-only and person-only in the gateway; read by `noo cluster
    # verify` through the flags list. Listed for parity.
    FlagSpec("at_rest.unencrypted_accepted", "security", False,
             "Unencrypted data at rest accepted",
             "Record that you accept this controller's data being stored unencrypted on disk "
             "(anyone with the drive can read it)."),
]

# Registered STRING settings (config-graduation phase 2). Same DB-override
# semantics as the boolean flags; values are stored/served as raw text and
# parsed at the read site. The authoritative registry (and the HTTP set
# endpoint) is gateway-rust/src/routes/settings.rs::STRING_REGISTRY — this
# mirror exists so Python readers can use get_setting() with the same default.
_STRING_SETTINGS: dict[str, str] = {
    # IANA timezone for heartbeat cron evaluation (read in Rust
    # heartbeat_actions::resolve_tz: DB row → env → yaml heartbeat.tz → this).
    "NOO_HEARTBEAT_TZ": "America/New_York",
    "NOO_OPS_WAIT_GRAPH_RECLUSTER_SECS": "0",
    "NOO_OPS_WAIT_GRAPH_EXTRACT_RELATIONS_SECS": "3",
    "NOO_OPS_WAIT_SNAPSHOTS_CONSOLIDATE_SECS": "3",
    "NOO_OPS_WAIT_GRAPH_NAVIGATE_SECS": "12",
    "NOO_OPS_WAIT_GRAPH_TRAVERSE_SECS": "12",
    "NOO_OPS_WAIT_RAG_INGEST_SECS": "3",
    "NOO_OPS_WAIT_DOCS_INGEST_SECS": "3",
    "NOO_OPS_WAIT_GRAPH_ENTITY_CLEANUP_SECS": "3",
    "NOO_OPS_RESULT_TTL_SECS": "86400",
}

REGISTRY: dict[str, FlagSpec] = {f.key: f for f in _FLAGS}

_cache: dict = {"at": 0.0, "rows": {}}


def _overrides() -> dict:
    """Return the noo_settings overrides (key→value), TTL-cached. Degrades to
    the last-known map (then empty) on any DB error — never raises."""
    now = time.monotonic()
    if _cache["at"] > 0 and now - _cache["at"] < _CACHE_TTL:
        return _cache["rows"]
    rows: dict = {}
    try:
        from sqlalchemy import text as _sql_text

        from .db import get_engine
        eng = get_engine()
        with eng.connect() as conn:
            for k, v in conn.execute(_sql_text("SELECT key, value FROM noo_settings")):
                rows[str(k)] = str(v)
    except Exception:
        rows = _cache.get("rows", {})
    _cache["rows"] = rows
    _cache["at"] = now
    return rows


def invalidate_cache() -> None:
    """Drop the TTL cache so the next read reflects a just-written override."""
    _cache["at"] = 0.0


def get_setting(key: str, default: "str | None" = None) -> "str | None":
    """Resolve a setting: DB override → env → default (raw string)."""
    ov = _overrides()
    if key in ov:
        return ov[key]
    env = os.environ.get(key)
    if env is not None:
        return env
    return default


def flag(key: str) -> bool:
    """Resolve a boolean behavioral flag (DB override → env → registered default)."""
    spec = REGISTRY.get(key)
    raw = get_setting(key)
    if raw is None:
        return spec.default if spec else False
    return raw.strip().lower() in _TRUTHY
