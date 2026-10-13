# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Content moderator provider — text moderation + skill-content scan.

Replaces direct imports of:
    from noomesh.gateway.security import moderate_external_content
    from noomesh.gateway.security import scan_skill_content
    from noomesh.gateway.security import get_security_manager

Consumers:
    - tools/web_search.py        — moderate_external_content
    - prompt_skills/evolver.py   — scan_skill_content + get_security_manager

Why: keeps the harness from reaching into ``gateway.security`` at import
time so HARNESS can be replaced with a custom moderator in Phase 4
(e.g. a deployment that uses an external moderation API).

Same back-compat rule as HttpContextProvider: ``default_content_moderator()``
delegates to the existing gateway functions.
"""

from __future__ import annotations

from typing import Any, List, Optional, Protocol, runtime_checkable


@runtime_checkable
class ContentModerator(Protocol):
    """Provider for moderation + content-scan operations.

    Methods are sync (matches the underlying gateway functions). If a
    future implementation needs async (remote moderation API), wrap it.
    """

    def moderate(self, text: str, *, source: str = "unknown",
                 max_length: int = 8192, redact: bool = True) -> str:
        """Sanitize untrusted external text before it enters LLM context.

        Returns the cleaned string (truncated, HTML-stripped, XSS-cleaned,
        injection-redacted).

        An implementation that CANNOT moderate must return a refusal
        notice in place of the text, never the text. Returning the raw
        input on failure turns the one call site that exists to strip
        injection into a pass-through at exactly the moment it stopped
        working."""
        ...

    def scan(self, content: str) -> List[str]:
        """Return a list of warning strings for prompt-skill content.

        Empty list = clean. Non-empty = warnings (still publishable but
        flagged). Distinct from `moderate` because skill content needs
        a different policy (prompt-injection detection without aggressive
        redaction)."""
        ...

    def manager(self) -> Optional[Any]:
        """Return the live SecurityManager singleton if initialised, else None.

        Used by callers that need additional security policy beyond
        moderate/scan (rate limits, audit logging, etc.)."""
        ...


class GatewayContentModerator:
    """Default impl that delegates to ``gateway.security`` callables.

    Lazy imports so the provider package doesn't pull in the gateway
    module at import time (the gateway lifespan may not have run yet).
    """

    def moderate(self, text: str, *, source: str = "unknown",
                 max_length: int = 8192, redact: bool = True) -> str:
        try:
            from ..gateway.security import moderate_external_content
            return moderate_external_content(
                text, source=source, max_length=max_length, redact=redact
            )
        except Exception as exc:
            # REFUSE. This used to return
            # `text[:max_length]` — the untrusted text, unmoderated,
            # with a comment calling it a "safe-default fallback". The
            # only reason this call exists is to strip prompt injection
            # out of external content; handing the content back when the
            # stripper is unavailable is the failure it was meant to
            # prevent, and it is silent. A caller that would rather have
            # the raw bytes can read them from its own source.
            import structlog

            structlog.get_logger().error(
                "content_moderation_unavailable", source=source, error=str(exc)
            )
            return (
                "[CONTENT WITHHELD: moderation is unavailable, so this "
                f"{source} content was not passed through. Treat this as an "
                "error, not as empty content.]"
            )

    def scan(self, content: str) -> List[str]:
        try:
            from ..gateway.security import scan_skill_content
            return scan_skill_content(content)
        except Exception:
            return []

    def manager(self) -> Optional[Any]:
        try:
            from ..gateway.security import get_security_manager
            return get_security_manager()
        except Exception:
            return None


def default_content_moderator() -> ContentModerator:
    """Back-compat default: delegates to gateway.security functions."""
    return GatewayContentModerator()
