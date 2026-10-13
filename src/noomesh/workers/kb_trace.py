# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Provenance and audience history on knowledge-base documents.

An operator reviewing the corpus needs to answer two questions about any
document: *where did it come from* and *who changed who can read it*. Both
live on the ``docs`` row, under ``metadata``:

``metadata.ingest``
    ``{by, via, at}`` written ONCE, by the first ingest that created the row.
    ``by`` is the authenticated account (null for an internal caller), ``via``
    a coarse label for the path, ``at`` an ISO-8601 UTC instant. Never a
    token, never a header value.

``metadata.audience_history``
    The last :data:`HISTORY_CAP` retags, oldest first, each
    ``{at, by, from, to}``.

Why this is written from the worker with SQL and not by a trellion store
method: ``PageIndexStore.insert_doc`` merges a re-ingest's metadata over the
existing row (new keys win), and ``set_doc_roles`` writes only
``metadata.roles``. Neither has a hook for a third key, and trellion is a
separate repository. Both writes below are best-effort additions to an
operation that has already succeeded; a failure is logged and reported, never
allowed to fail the ingest or the retag it describes.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

import structlog

log = structlog.get_logger(__name__)

HISTORY_CAP = 20

# Keys a caller may not set through ``metadata`` on ingest: they are facts
# the system records, and a person who could write them could forge the
# trail an operator reviews.
RESERVED_METADATA_KEYS = ("ingest", "audience_history")

_FOLDER_KINDS = {"watched_folder": "folder", "watched_drive": "drive"}
_URI_SCHEMES = (
    ("heartbeat://", "heartbeat"),
    ("research://", "research"),
    ("gdrive://", "drive"),
)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ingest_via(requester: dict, source_uri: Optional[str], metadata: Optional[dict]) -> str:
    """The coarse path an ingest arrived by, from what the request carries.

    * Any request with an authenticated requester was made by a person's
      credential: ``mcp`` when the credential came from the MCP door (its
      signed ``harness`` claim is ``mcp-external:<consumer>``; the user and
      operator doors mint the same claim, so they are not told apart),
      ``upload`` for the multipart upload route (``upload://``), ``cli`` for
      ``noo rag ingest`` (the only sender of ``file://``), else ``api``.
    * No requester is an internal caller (cluster HMAC): the ingest loop says
      ``metadata.source_kind``; heartbeats, research and Drive say it in the
      ``source_uri`` scheme; anything else is ``internal``.

    ``metadata.source_kind`` and the scheme are only trusted when there is no
    requester; a person cannot label their own upload as a folder scan.
    ``by`` is the authenticated fact; ``via`` is a best-effort label.
    """
    uri = str(source_uri or "")
    if requester:
        harness = str(requester.get("harness") or "")
        if harness.startswith("mcp-external:"):
            return "mcp"
        if uri.startswith("upload://"):
            return "upload"
        if uri.startswith("file://"):
            return "cli"
        return "api"
    kind = str((metadata or {}).get("source_kind") or "")
    if kind in _FOLDER_KINDS:
        return _FOLDER_KINDS[kind]
    for prefix, label in _URI_SCHEMES:
        if uri.startswith(prefix):
            return label
    return "internal"


def ingest_block(requester: dict, uploader: str, source_uri: Optional[str],
                 metadata: Optional[dict]) -> dict:
    return {
        "by": uploader or None,
        "via": ingest_via(requester, source_uri, metadata),
        "at": now_iso(),
    }


def merge_history(existing: Any, entry: dict, cap: int = HISTORY_CAP) -> list:
    """Append *entry* to a stored history, keeping the newest *cap* items."""
    items = list(existing) if isinstance(existing, list) else []
    items.append(entry)
    return items[-cap:]


def _engine(store: Any) -> Any:
    return getattr(store, "_engine", None)


def _json(v: Any) -> Any:
    """A jsonb column as a Python value, whether the driver decoded it or not."""
    if isinstance(v, (str, bytes)):
        try:
            return json.loads(v)
        except ValueError:
            return None
    return v


async def _read(engine: Any, doc_ids: list[str]) -> dict[str, dict]:
    from sqlalchemy import text

    async with engine.connect() as conn:
        res = await conn.execute(
            text(
                "SELECT doc_id::text, created_at, metadata->'ingest', "
                "       metadata->'audience_history' "
                "FROM docs WHERE doc_id = ANY(CAST(:ids AS uuid[]))"
            ),
            {"ids": list(doc_ids)},
        )
        return {
            str(r[0]): {"created_at": r[1], "ingest": _json(r[2]), "history": _json(r[3])}
            for r in res.fetchall()
        }


async def _patch(engine: Any, patches: dict[str, dict]) -> None:
    from sqlalchemy import text

    async with engine.connect() as conn:
        for doc_id, patch in patches.items():
            await conn.execute(
                text(
                    "UPDATE docs SET metadata = COALESCE(metadata, '{}'::jsonb) "
                    "|| CAST(:patch AS jsonb) WHERE doc_id = CAST(:id AS uuid)"
                ),
                {"id": doc_id, "patch": json.dumps(patch)},
            )
        await conn.commit()


async def record_ingest(store: Any, doc_id: str, block: dict) -> bool:
    """Write ``metadata.ingest`` onto a row the caller has just CREATED.

    Whether the row is new is decided by ``kb_ingest_roles.settle_roles``;
    a dedup hit never reaches here, so the first ingest's
    block is kept and a document from before provenance stays ``unknown``.
    Best-effort: a failure is logged and never fails the ingest. Returns
    whether it was written.
    """
    engine = _engine(store)
    if engine is None or not doc_id:
        return False
    try:
        await _patch(engine, {str(doc_id): {"ingest": block}})
        return True
    except Exception as e:  # noqa: BLE001
        log.warning("kb_trace.ingest_record_failed", doc_id=str(doc_id), error=str(e))
        return False


async def record_retag(store: Any, changes: list[dict], by: str,
                       cap: int = HISTORY_CAP) -> Optional[str]:
    """Append ``{at, by, from, to}`` to each changed document's history.

    *changes* is ``[{doc_id, from, to}]``. Returns None on success or the
    error text, which the caller reports instead of raising: by now the
    audience HAS changed and the caller must be told that, not handed an
    error that reads as "nothing happened".
    """
    if not changes:
        return None
    engine = _engine(store)
    if engine is None:
        return "no database handle on the store; audience_history not written"
    try:
        current = await _read(engine, [c["doc_id"] for c in changes])
        at = now_iso()
        patches = {}
        for c in changes:
            entry = {"at": at, "by": by, "from": list(c["from"]), "to": list(c["to"])}
            prior = (current.get(c["doc_id"]) or {}).get("history")
            patches[c["doc_id"]] = {"audience_history": merge_history(prior, entry, cap)}
        await _patch(engine, patches)
        return None
    except Exception as e:  # noqa: BLE001
        log.warning("kb_trace.history_failed", error=str(e))
        return f"audience_history not written: {e}"
