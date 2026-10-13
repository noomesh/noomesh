# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Console tracebacks must not dump frame locals.

Regression guard: with
`rich` installed, structlog's ConsoleRenderer defaults to a rich traceback
rendered with ``show_locals=True``. An exception raised inside psycopg then
printed that frame's ``conninfo`` local — which contains the Postgres password
in cleartext — to stdout, where the log shipper (promtail then, the node-agent now) shipped it to Loki. Observed in
noo-trellion on a Postgres connection refusal.
"""

from __future__ import annotations

import io

import pytest
import structlog

from noomesh._logging import _exception_formatter, configure_logging


def test_exception_formatter_disables_locals():
    fmt = _exception_formatter()
    show_locals = getattr(fmt, "show_locals", False)
    assert show_locals is False, "traceback formatter must not render frame locals"


def test_console_traceback_omits_local_variables():
    """End-to-end: a secret held in a frame local must not reach the output.

    The secret is assembled at runtime so it cannot appear in this file's
    source — rich renders the failing *source line* either way, and only the
    runtime value is what leaked in the real incident.
    """
    secret = "".join(["hunter", "2-", "must-not-be-logged"])  # noqa: S105

    def _boom(password: str):
        conninfo = f"host=postgres user=noo password={password}"  # noqa: F841
        raise RuntimeError("connection failed")

    buf = io.StringIO()
    fmt = _exception_formatter()
    try:
        _boom(secret)
    except RuntimeError:
        import sys

        fmt(buf, sys.exc_info())

    rendered = buf.getvalue()
    # The traceback itself must still be useful...
    assert "RuntimeError" in rendered or "connection failed" in rendered
    # ...but must not carry the runtime value of any frame local.
    assert secret not in rendered, "frame locals leaked into the rendered traceback"


def test_configure_logging_console_mode_still_works():
    """The explicit formatter must not break normal console configuration."""
    configure_logging(level="INFO", json_logs=False)
    log = structlog.get_logger("audit-test")
    log.info("hello", key="value")  # must not raise


def test_configure_logging_json_mode_unaffected():
    configure_logging(level="INFO", json_logs=True)
    log = structlog.get_logger("audit-test")
    log.info("hello", key="value")
    configure_logging(level="INFO", json_logs=False)  # restore


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
