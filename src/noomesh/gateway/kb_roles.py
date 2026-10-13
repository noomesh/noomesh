# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Source→role mapping for KB ingestion.

Documents inherit audience roles from WHERE they came from: a shared
Drive folder or Google Chat digest is born ``company``/``team``; a user's
personal folder is born ``user:<name>``; repo runbooks are ``system``.
Explicit ``roles`` on the ingest call always win; this mapping fills in
when the caller didn't say.

Configured in ``noomesh.yaml``::

    kb:
      # First glob match wins (fnmatch against source_uri AND source path)
      source_roles:
        - match: "runbook://*"
          roles: [system]
        - match: "gdrive://*"
          roles: [company]
        - match: "/data/ingest/users/alice/*"
          roles: ["user:alice"]
        - match: "channel:google_chat*"
          roles: [team]
      # Applied when nothing matches AND the ingest has no uploader
      # identity (watched folders, Drive, internal loops). An upload by a
      # known account defaults to that account's own user:<sub> instead.
      # Empty → admin-only (an explicit `admin` tag, never an absent one).
      default_roles: []

Every automated ingest path (watched folders, the Drive loop, the API)
funnels through ``worker.rag.ingest``, so this single mapping governs all
provenance.
"""
from __future__ import annotations

import os
import time
from fnmatch import fnmatch
from typing import Any, Optional

import structlog

log = structlog.get_logger(__name__)

_CONFIG_CANDIDATES = ("/app/noomesh.yaml", "noomesh.yaml")
_CACHE_TTL_SECS = 30.0

_cache: dict[str, Any] = {"loaded_at": 0.0, "rules": [], "default_roles": []}


def _load_kb_config() -> None:
    """(Re)load kb.source_roles from the config YAML, cached briefly so
    hot ingest loops don't re-read the file per document."""
    now = time.monotonic()
    if now - _cache["loaded_at"] < _CACHE_TTL_SECS:
        return
    _cache["loaded_at"] = now
    rules: list[tuple[str, list[str]]] = []
    default_roles: list[str] = []
    for path in _CONFIG_CANDIDATES:
        if not os.path.isfile(path):
            continue
        try:
            import yaml
            with open(path) as fh:
                cfg = yaml.safe_load(fh) or {}
        except Exception as e:  # noqa: BLE001 — config problems must not break ingest
            log.warning("kb_roles.config_unreadable", path=path, error=str(e))
            return
        kb = cfg.get("kb") or {}
        for rule in kb.get("source_roles") or []:
            match = str(rule.get("match") or "").strip()
            roles = [str(r) for r in (rule.get("roles") or []) if str(r).strip()]
            if match and roles:
                rules.append((match, roles))
        default_roles = [str(r) for r in (kb.get("default_roles") or []) if str(r).strip()]
        break
    _cache["rules"] = rules
    _cache["default_roles"] = default_roles


def default_roles() -> list[str]:
    """``kb.default_roles`` — the audience for an ingest with NO uploader
    identity and no matching source rule. Empty when unset."""
    _load_kb_config()
    return list(_cache["default_roles"])


def resolve_source_roles(
    *sources: Optional[str],
    extra_rules: Optional[list] = None,
    include_default: bool = True,
) -> Optional[list[str]]:
    """Roles for a document based on its provenance strings (source_uri,
    file path, ...). ``extra_rules`` (DB-backed noo_kb_source_rules,
    admin-editable at runtime) are checked FIRST, then the YAML rules,
    then (unless ``include_default=False``) ``kb.default_roles``; returns
    None when nothing applies. The caller owns the final fallback — a
    document is never stored without an audience."""
    _load_kb_config()
    candidates = [s for s in sources if s]
    for pattern, roles in list(extra_rules or []) + list(_cache["rules"]):
        for s in candidates:
            if fnmatch(s, pattern):
                return list(roles)
    if not include_default:
        return None
    return list(_cache["default_roles"]) or None
