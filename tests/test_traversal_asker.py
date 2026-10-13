# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Who asked a graph walk (noomesh an earlier change): the verified ACCOUNT, never the body.

The value is stamped on ``trellion_traversal_records.user_id`` and matched by
trellion-intel's recall against ``user:<account>`` roles, so its form is a
contract. The end-to-end archive -> recall pin lives in the trellion-intel add-on
(``tests/test_audience_scoping.py``); this pins the half that is ours.
"""
from __future__ import annotations

import pytest

from noomesh.gateway import bus_principal as bp
from noomesh.workers.audience import asker_account
from tests.test_bus_principal import KEYS, _sign


@pytest.fixture(autouse=True)
def _worker_env(monkeypatch):
    monkeypatch.setenv("NOO_BUS_KEY", KEYS["worker"])
    monkeypatch.setenv("NOO_BUS_AUDIENCE", "worker")
    bp.reset_nonce_cache()
    yield
    bp.reset_nonce_cache()


def _request(body=None, **sign):
    principal = bp.verify_token(_sign(**sign), sign.get("subj", "worker.rag.query"))
    return bp.apply_to_request(dict(body or {}), principal)


def test_the_account_is_taken_from_a_connection_subject():
    assert asker_account(_request(sub="alice/laptop", nonce="c1")) == "alice"


def test_a_bare_account_is_itself():
    assert asker_account(_request(sub="alice", nonce="c2")) == "alice"


def test_it_is_the_form_the_kb_audience_and_recall_match():
    """`user:<account>` is in the caller's roles for exactly this account."""
    from noomesh.workers.kb import _resolve_kb_roles

    req = _request(sub="alice/laptop", nonce="c3")
    assert f"user:{asker_account(req)}" in _resolve_kb_roles(req)


def test_a_forged_requester_in_the_body_is_overwritten_not_believed():
    req = _request(
        {"_requester": {"sub": "root", "scopes": ["admin"]}, "params": {"_requester": {"sub": "root"}}},
        sub="alice", nonce="c4",
    )
    assert asker_account(req) == "alice"


def test_a_forged_user_id_is_refused_or_ignored_never_taken():
    principal = bp.verify_token(_sign(sub="alice", nonce="c5"), "worker.rag.query")
    with pytest.raises(bp.PrincipalError):  # the delegation guard refuses it outright
        bp.apply_to_request({"user_id": "victim"}, principal)
    # And a handler that is handed the unsigned body anyway gets no asker.
    assert asker_account({"user_id": "victim", "_requester": {"sub": "victim"}}) is None


def test_an_unsigned_request_has_no_asker():
    assert asker_account({}) is None
    assert asker_account({"_requester": {"sub": "alice", "scopes": ["admin"]}, "user_id": "alice"}) is None


def test_an_internal_walk_stays_unattributed_even_if_the_body_names_a_user():
    """A heartbeat acts FOR somebody, but 'for whom' is the body's claim."""
    req = _request(
        {"user_id": "alice"},
        sub="internal:heartbeat", kind="internal", scopes=["read", "write"],
        subj="worker.api.heartbeat.run", nonce="c6",
    )
    assert asker_account(req) is None
