# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`cli_httpx_kwargs()` must be able to send a *named* credential.

Phase 3 of the CLI auth plan makes the gateway refuse the
fleet-shared cluster HMAC on `POST /api/approval/{id}/decide` — an approval
decision has to be attributable to a person. The Python CLI had no per-user
path at all (it only ever minted a cluster-HMAC bearer), so without
`$NOO_TOKEN` precedence it would be permanently locked out of that route.

Order is the point, not merely the presence of the branch: an operator who
exports `NOO_TOKEN` while `NOO_CLUSTER_SECRET` is still in the environment —
which is the normal state on the controller — must send the JWT. And with no
`NOO_TOKEN` there is no fallback any more: the command refuses
(`tests/test_cli_no_shared_secret.py`).
"""
from __future__ import annotations

import pytest

from noomesh.cli_utils import cli_httpx_kwargs


@pytest.fixture(autouse=True)
def _no_repo_env(monkeypatch):
    """`cli_httpx_kwargs` calls `ensure_repo_env()`, which loads the repo
    `.env` and would reintroduce a real `NOO_CLUSTER_SECRET` mid-test."""
    monkeypatch.setattr("noomesh.cli_utils.ensure_repo_env", lambda *a, **k: None)


def _bearer(kwargs: dict) -> str | None:
    return kwargs.get("headers", {}).get("Authorization")


def test_noo_token_wins_over_the_cluster_secret(monkeypatch):
    monkeypatch.setenv("NOO_TOKEN", "jwt-abc")
    monkeypatch.setenv("NOO_CLUSTER_SECRET", "shared-fleet-secret")
    assert _bearer(cli_httpx_kwargs()) == "Bearer jwt-abc"


def test_blank_noo_token_refuses_rather_than_signing(monkeypatch, capsys):
    """An empty export must not send `Bearer `, and must not fall back to a
    shared secret either: the HMAC fallback is gone."""
    monkeypatch.setenv("NOO_TOKEN", "   ")
    monkeypatch.setenv("NOO_CLUSTER_SECRET", "shared-fleet-secret")
    with pytest.raises(SystemExit) as exc:
        cli_httpx_kwargs()
    assert exc.value.code == 2
    assert "no longer signs" in capsys.readouterr().err


def test_neither_credential_refuses(monkeypatch, capsys):
    monkeypatch.delenv("NOO_TOKEN", raising=False)
    monkeypatch.delenv("NOO_CLUSTER_SECRET", raising=False)
    with pytest.raises(SystemExit):
        cli_httpx_kwargs()
    assert "noo auth login" in capsys.readouterr().err
