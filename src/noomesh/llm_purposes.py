# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The purposes a worker-side caller names instead of a model (proposal i145).

A caller sends one of these as ``model`` to the gateway's
``/v1/chat/completions``; the gateway's class table says what it means
(``coordinator::classes::PURPOSE_ALIASES``). Undeclared, a purpose is the
whole mesh. An operator steers one with ``noo cluster class set <class> …
--alias knowledge``, in the DB, so no env value restates the choice.

``PAGEINDEX_LLM_URL`` / ``PAGEINDEX_LLM_MODEL`` used to do that from the env.
Compose no longer passes them and nothing reads them; the launcher warns about
a leftover ``.env`` line (``scripts/retired-env-keys``).
"""
from __future__ import annotations

import os

#: trellion: answers, page ingestion and its graph extraction.
KNOWLEDGE = "knowledge"
#: the worker's conversation (temporal) extraction.
GRAPH = "graph"


def gateway_url() -> str:
    """The gateway's address from inside a stack container (https only)."""
    return (os.getenv("NOO_GATEWAY_URL") or "https://gateway:8080").rstrip("/")

