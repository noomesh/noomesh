# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Provider protocols — HARNESS/MESH injection surface.

By design ("parameterize, don't move"), modules that
currently reach into ``noomesh.gateway.*`` globals at runtime should
instead accept the same data via constructor arguments.

This package defines the Protocols that those constructor args satisfy.
Each Protocol has a "default" factory that pulls from the existing
gateway globals — so the migration is non-breaking: consumers swap
``from .gateway.deps import ssl_verify, client_cert`` for an injected
``http_context`` arg with a default that does the old lookup.

Once HARNESS becomes its own repo (Phase 4), the harness lifespan
constructs the providers from its own config (or uses a different
implementation entirely, e.g. a third-party harness with its own
mTLS strategy) and passes them in. MESH no longer needs to expose
``gateway.deps`` to harness code.

Underscore prefix (``_providers``) marks this as an internal API
surface that's stable for harness consumers but not part of the public
``noomesh`` namespace.
"""

from .http_context import HttpContextProvider, default_http_context
from .content_moderator import ContentModerator, default_content_moderator
from .exec_approval_gate import (
    ApprovalDecision,
    ApprovalRequest,
    ExecApprovalGate,
    default_exec_approval_gate,
)
from .coding_task_runner import CodingTaskRunner, default_coding_task_runner
from .backend_resolver import BackendResolver, default_backend_resolver
from .settings_store import SettingsStoreProvider, default_settings_store
from .conversation_store import ConversationStoreProvider, default_conversation_store

__all__ = [
    "HttpContextProvider", "default_http_context",
    "ContentModerator", "default_content_moderator",
    "ExecApprovalGate", "ApprovalRequest", "ApprovalDecision",
    "default_exec_approval_gate",
    "CodingTaskRunner", "default_coding_task_runner",
    "BackendResolver", "default_backend_resolver",
    "SettingsStoreProvider", "default_settings_store",
    "ConversationStoreProvider", "default_conversation_store",
]
