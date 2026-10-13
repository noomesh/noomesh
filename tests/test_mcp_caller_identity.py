# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Caller identity binding for `worker.tool.generic` dispatch.

The property under test: a dispatch bound to a Mesh user presents THE TOKEN
THE GATEWAY MINTED for that dispatch, never one this process
mints, and never the operator credential; an unbound dispatch keeps using the
container's own service credential exactly as before.

The failure this guards against is silent: if identity is dropped anywhere
between the handler and the outbound request, every call still succeeds — it
just succeeds with operator privileges. So these assert on the Authorization
header that actually goes out, not on intermediate plumbing.
"""
from __future__ import annotations

import contextvars

import pytest

from noomesh.mcp import tool_models
from noomesh.mcp.tool_models import (
    AuthLevel,
    DelegationMissing,
    _auth_headers,
    set_caller_identity,
)

DELEGATED = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsifQ.gateway-minted.sig"


@pytest.fixture(autouse=True)
def _no_signing_secret_anywhere(monkeypatch):
    """The worker holds no NOO_JWT_SECRET. If anything on this path still
    asked for it, the guard fails the test outright."""
    monkeypatch.delenv("NOO_JWT_SECRET", raising=False)
    monkeypatch.delenv("NOO_JWT_SECRET_FILE", raising=False)
    import noomesh.secrets as _secrets

    real = _secrets.get_secret

    def _guard(k, d=""):
        assert k != "NOO_JWT_SECRET", "the tool dispatch path asked for the login signing secret"
        return real(k, d)

    monkeypatch.setattr("noomesh.secrets.get_secret", _guard)


def _in_fresh_context(fn):
    """Run fn in its own context so a set_caller_identity doesn't leak."""
    return contextvars.copy_context().run(fn)


def test_unbound_caller_dispatches_as_operator(monkeypatch):
    """No bound identity → the container's own key, untouched."""
    monkeypatch.setenv("NOO_GATEWAY_KEY", "noo-sk-worker-own")
    headers = _in_fresh_context(lambda: _auth_headers(AuthLevel.CLUSTER))
    assert headers["Authorization"] == "Bearer noo-sk-worker-own"


def test_unbound_caller_without_a_key_sends_no_shared_secret(monkeypatch):
    """an earlier change: with no key of its own the dispatcher sends NOTHING —
    never a cluster HMAC, whatever shared secret the container holds."""
    monkeypatch.delenv("NOO_GATEWAY_KEY", raising=False)
    monkeypatch.setenv("NOO_CLUSTER_SECRET", "fleet-secret")
    monkeypatch.setenv("NOO_CONTROLLER_SECRET", "controller-secret")
    headers = _in_fresh_context(lambda: _auth_headers(AuthLevel.CLUSTER))
    assert "Authorization" not in headers, headers


@pytest.mark.parametrize("level", [AuthLevel.CLUSTER, AuthLevel.JWT])
def test_bound_caller_presents_the_gateway_token_verbatim(level):
    def _run():
        set_caller_identity("carol", ["read"], DELEGATED)
        return _auth_headers(level)

    assert _in_fresh_context(_run) == {"Authorization": f"Bearer {DELEGATED}"}


def test_bound_caller_without_a_token_refuses_and_never_mints(monkeypatch):
    """Fail closed, by name. No local mint (there is no secret to mint
    with, by design) and no fall-through to the operator credential."""
    monkeypatch.setenv("NOO_GATEWAY_KEY", "noo-sk-worker-own")
    monkeypatch.setattr(
        "noomesh.cluster.cluster_auth.create_cluster_token",
        lambda actor, **kw: f"hmac-{actor}",
    )

    def _run():
        set_caller_identity("carol", ["read"])
        return _auth_headers(AuthLevel.CLUSTER)

    with pytest.raises(DelegationMissing, match="no delegated token"):
        _in_fresh_context(_run)


def test_identity_does_not_leak_across_contexts():
    def _bind():
        set_caller_identity("carol", ["read"], DELEGATED)
        return tool_models.get_caller_identity()

    assert _in_fresh_context(_bind) == ("carol", ["read"])
    assert tool_models.get_caller_identity() is None
