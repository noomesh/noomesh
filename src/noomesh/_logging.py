# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Centralised structured logging for the Mesh codebase.

Usage — every file should use exactly one pattern::

    from noomesh._logging import get_logger
    log = get_logger(__name__)

    log.info("thing_happened", key="value", count=42)

This guarantees:
- Structured key=value output via structlog
- Source module name with colour-coded prefix
- Consistent formatting across all 150+ modules
- No ``import logging`` / ``import structlog`` drift

Configuration is done once at startup via :func:`configure_logging`.
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Dict

import structlog


# ── Module name shortener ──────────────────────────────────────────────

# Map long module paths to short labels for log output.
# "noomesh.memory.pageindex_store" → "pageindex_store"
# "noomesh.gateway.coordinator"    → "coordinator"

def _add_short_module(
    logger: Any, method_name: str, event_dict: Dict[str, Any],
) -> Dict[str, Any]:
    """Add a short ``module`` field derived from the logger name."""
    name = event_dict.get("logger", event_dict.get("_logger_name", ""))
    if name:
        # Strip common prefixes: noomesh.gateway.foo → foo
        #                        noomesh.memory.video.bar → video.bar
        parts = name.split(".")
        # Drop "noomesh" prefix and one level of package
        if len(parts) >= 3 and parts[0] == "noomesh":
            parts = parts[2:]  # e.g. ["pageindex_store"] or ["video", "manager"]
        event_dict["module"] = ".".join(parts) if parts else name
    else:
        event_dict["module"] = "unknown"
    return event_dict


def _inject_module_prefix(
    logger: Any, method_name: str, event_dict: Dict[str, Any],
) -> Dict[str, Any]:
    """Prepend ``[module_name]`` to the event string for console output.

    This makes it easy to visually scan which subsystem produced each line
    without needing Grafana/Loki.  The ``module`` key is removed from
    the event dict so it doesn't also appear as a key=value pair.
    """
    module = event_dict.pop("module", "")
    if module:
        event = event_dict.get("event", "")
        event_dict["event"] = f"\033[36m[{module}]\033[0m {event}"
    return event_dict


# ── Configuration ──────────────────────────────────────────────────────


def _exception_formatter() -> Any:
    """Traceback renderer for console mode, with local variables OFF.

    SECURITY: when `rich`
    is installed, structlog's ConsoleRenderer defaults to a rich traceback with
    ``show_locals=True``. Any exception raised inside a DB driver then dumps
    that frame's locals — including psycopg's ``conninfo`` string, which
    carries the Postgres password in cleartext — into stdout, which the log shipper
    ships to Loki. Observed in noo-trellion on a Postgres connection refusal.

    Locals are worth little in a shipped log and are a standing credential
    leak, so pin the formatter explicitly rather than inheriting the default.
    """
    try:
        return structlog.dev.RichTracebackFormatter(show_locals=False)
    except AttributeError:  # older structlog, or rich absent
        return structlog.dev.plain_traceback


def configure_logging(
    level: str = "INFO",
    json_logs: bool = False,
    include_timestamp: bool = True,
) -> None:
    """Configure structured logging for the application.

    Call once at startup (gateway lifespan, CLI entry, tests).
    """
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
    )

    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        _add_short_module,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if include_timestamp:
        processors.append(structlog.processors.TimeStamper(fmt="iso"))

    if json_logs:
        # JSON mode: module field is automatically included and queryable
        # in Loki via {module="pageindex_store"}
        processors.append(structlog.processors.JSONRenderer())
    else:
        # Console mode: inject module name into the event for visibility
        # Output: "2026-03-24 [info] [pageindex_store] ingest event=..."
        processors.extend([
            _inject_module_prefix,
            structlog.processors.ExceptionPrettyPrinter(),
            structlog.dev.ConsoleRenderer(
                colors=True,
                exception_formatter=_exception_formatter(),
            ),
        ])

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


# ── Logger factory ─────────────────────────────────────────────────────


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a structured logger.  **This is the only import you need.**

    Args:
        name: Typically ``__name__`` — used as the logger name prefix.

    Returns:
        A bound structlog logger that supports ``log.info("event", k=v)``
        syntax.  Under the hood this delegates to stdlib logging so all
        existing handlers, filters, and formatters work.
    """
    return structlog.get_logger(name)


# ── Convenience helpers (optional) ─────────────────────────────────────


def log_tool_execution(
    logger: structlog.stdlib.BoundLogger,
    tool_name: str,
    args: Dict[str, Any],
    success: bool,
    duration_ms: float,
    error: str | None = None,
    session_id: str | None = None,
) -> None:
    """Log a tool call with standardised fields."""
    truncated_args = {
        k: (v[:100] + "..." if isinstance(v, str) and len(v) > 100 else v)
        for k, v in args.items()
    }
    kw: Dict[str, Any] = {
        "tool_name": tool_name,
        "args": truncated_args,
        "success": success,
        "duration_ms": duration_ms,
    }
    if session_id:
        kw["session_id"] = session_id
    if error:
        kw["error"] = error
        logger.error("tool_execution", **kw)
    else:
        logger.info("tool_execution", **kw)


def log_llm_call(
    logger: structlog.stdlib.BoundLogger,
    model: str,
    messages_count: int,
    tools_count: int,
    success: bool,
    duration_ms: float,
    tokens_used: int | None = None,
    error: str | None = None,
    session_id: str | None = None,
) -> None:
    """Log an LLM API call with standardised fields."""
    kw: Dict[str, Any] = {
        "model": model,
        "messages_count": messages_count,
        "tools_count": tools_count,
        "success": success,
        "duration_ms": duration_ms,
    }
    if tokens_used is not None:
        kw["tokens_used"] = tokens_used
    if session_id:
        kw["session_id"] = session_id
    if error:
        kw["error"] = error
        logger.error("llm_call", **kw)
    else:
        logger.info("llm_call", **kw)
