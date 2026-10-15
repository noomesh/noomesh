# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The replies this process owes, so a refused one is named rather than lost.

NATS reports a refused publish ASYNCHRONOUSLY: ``msg.respond`` returns as
if it worked, and the only trace is an error callback carrying
``nats: permissions violation for publish to "<subject>"`` — lowercased by
nats-py, with nothing saying it was the answer to a request. That is how i69
looked on pop-os: a ``rag_generator.done`` line, then a bare
``nats_async_error``, and a caller that never got its answer.

The worker records each reply subject when a request arrives; the error
callback asks :func:`refused_reply` whether a refused subject was one of
them, and logs ``worker.reply_undeliverable`` naming the request subject and
how long it had been held. Bounded and in-memory: it is a diagnostic, never a
gate.
"""

from __future__ import annotations

import re
import time
from collections import OrderedDict

#: Entries kept at most. nats-server's own reply-permission map prunes at
#: 4096, so a busier ledger would be tracking replies the server forgot.
MAX_ENTRIES = 4096

_VIOLATION = re.compile(r'permissions violation for publish to "([^"]+)"', re.IGNORECASE)

# lowercased reply subject -> (request subject, monotonic receive time)
_owed: "OrderedDict[str, tuple[str, float]]" = OrderedDict()


def received(reply: str | None, subject: str) -> None:
    """Note that *subject* arrived asking for an answer on *reply*."""
    if not reply:
        return
    key = reply.lower()
    _owed[key] = (subject, time.monotonic())
    _owed.move_to_end(key)
    while len(_owed) > MAX_ENTRIES:
        _owed.popitem(last=False)


def refused_reply(error_text: str) -> dict | None:
    """The owed reply an async NATS error refers to, or ``None``.

    ``None`` for any error that is not a publish permission violation, and
    for a violation on a subject this process was never asked to answer —
    that one is a different bug and keeps its generic log line.
    """
    m = _VIOLATION.search(error_text or "")
    if not m:
        return None
    hit = _owed.pop(m.group(1).lower(), None)
    if hit is None:
        return None
    subject, at = hit
    return {
        "request_subject": subject,
        "reply_subject": m.group(1),
        "held_s": round(time.monotonic() - at, 3),
    }


def _reset() -> None:
    """Tests only."""
    _owed.clear()
