# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PersonifAI LLC

"""The package's exceptions. Every one is a `GatewayError`."""

from __future__ import annotations


class GatewayError(Exception):
    """Base class for everything this package raises."""


class GatewayAuthUnavailable(GatewayError):
    """No credential lane can open the route, so NOTHING was sent.

    Raised locally by `GatewayAuth` when the exchange has failed (or its
    circuit is open) and the route is off the inference surface, or when the
    add-on has no `NOO_GATEWAY_KEY` at all. The gateway sees no traffic for
    it — that is the storm stop.
    """

    def __init__(self, method: str, path: str, reason: str) -> None:
        super().__init__(f"no credential can open {method} {path}: {reason}")
        self.method = method
        self.path = path
        self.reason = reason


class GatewayRefused(GatewayError):
    """The gateway answered 401 or 403. `reason` is the body's error, if any."""

    def __init__(self, status: int, method: str, path: str, reason: str) -> None:
        super().__init__(f"{method} {path} refused: HTTP {status}: {reason}")
        self.status = status
        self.method = method
        self.path = path
        self.reason = reason


class GatewayThrottled(GatewayError):
    """429 `consumer_quota_exceeded` — not a refusal; retry after `retry_after` seconds."""

    def __init__(self, method: str, path: str, retry_after: float | None, reason: str) -> None:
        super().__init__(f"{method} {path} throttled: {reason} (retry_after={retry_after})")
        self.method = method
        self.path = path
        self.retry_after = retry_after
        self.reason = reason


class GatewayResponseError(GatewayError):
    """Any other non-2xx answer from a `*_json` helper."""

    def __init__(self, status: int, method: str, path: str, reason: str) -> None:
        super().__init__(f"{method} {path} failed: HTTP {status}: {reason}")
        self.status = status
        self.method = method
        self.path = path
        self.reason = reason


def reason_from_body(body: object) -> str:
    """The gateway's error, from any of its body shapes, as one line.

    `{"error": {"type": "...", "message": "..."}}` (the doors),
    `{"error": "..."}` (most handlers), `{"detail": "..."}` (FastAPI-era),
    else the body's text, cut short.
    """
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            typ = str(err.get("type") or "")
            msg = str(err.get("message") or "")
            return f"{typ}: {msg}" if typ and msg else (typ or msg or "error")
        if isinstance(err, str) and err:
            return err
        detail = body.get("detail")
        if isinstance(detail, str) and detail:
            return detail
    text = str(body).strip()
    return text[:200] if text else "no reason given"
