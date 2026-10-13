# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The audience a graph/curriculum request arrives with.

Shared by ``graph.py`` (Intelligent-tier graph routes) and ``snapshots.py``
(curriculum). Registers no subject, so it needs no entry in the surface lists.

The gateway resolves the caller's knowledge-base audience ONCE
(``worker.rag.audience``, the one resolver, ``workers/kb.py::_kb_roles_for``)
and puts it in the body as ``roles``: absent = unrestricted, a list = the tags
the caller may read. It strips any ``roles`` the client sent before setting
its own. The worker does not re-derive it; it refuses the one shape that
cannot be right (a verified, non-privileged USER principal arriving with no
audience), and echoes ``audience_filtered: true`` on every reply it produced
under a verified restricted call. The gateway is fail-closed on that echo: a
reply without it is never forwarded to a restricted caller, which is what makes
an older worker, or a worker over an older trellion-intel, safe to run behind a
newer gateway.
"""

from __future__ import annotations

#: The echo. Spelled once, here; the gateway reads the same key.
AUDIENCE_KEY = "audience_filtered"


def audience_of(request: dict) -> "tuple[list[str] | None, dict | None]":
    """``(roles, error)``. ``roles`` None = unrestricted."""
    raw = request.get("roles")
    if raw is None:
        from ..gateway import bus_principal

        principal = bus_principal.of(request)
        if principal is not None and principal.is_user and not principal.kb_unrestricted:
            return None, {
                "error": "a restricted caller reached this worker without an audience"
            }
        return None, None
    if not isinstance(raw, list) or not all(isinstance(r, str) for r in raw):
        return None, {"error": "audience roles must be a list of strings"}
    return list(raw), None


def asker_account(request: dict) -> "str | None":
    """The ACCOUNT that asked, for stamping on what a walk leaves behind.

    ``trellion_traversal_records.user_id`` is what lets
    trellion-intel's audience-scoped recall show a user their own past
    questions. Recall matches it against the caller's ``user:<account>`` roles
    (the add-on's own-user-id matching), so the value must be the bare
    account, and it must come from the VERIFIED principal:

    * the principal's ``sub`` is the CONNECTION (``alice/laptop``); the
      account is ``account_of(sub)`` (``alice``), the same reduction the KB
      audience uses (``kb._account_of``);
    * never from the body. ``bus_principal.apply_to_request`` already
      overwrites ``_requester`` and refuses a mismatched ``user_id`` for a
      user principal, and this reads neither: an unsigned request, or a body
      that merely CLAIMS an identity, is ``None``;
    * only a ``user`` principal has an asker. An ``internal`` one (heartbeat,
      autonomy) may name a user it acts for in the body, but that is the
      body's say-so, so its walks stay unattributed (NULL).
    """
    from ..gateway import bus_principal
    from .kb import _account_of

    principal = bus_principal.of(request)
    if principal is None or not principal.is_user:
        return None
    return _account_of(principal.sub.strip()) or None
