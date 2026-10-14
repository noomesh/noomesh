# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A refused worker reply is logged as the lost answer it is (i69).

nats-py reports a refused publish only through the async error callback,
lowercased and with no request context. Before, that was a bare
`nats_async_error`; the caller just timed out.
"""

import pytest

from noomesh.cluster import reply_ledger
from noomesh.cluster.messaging import ClusterMessaging


@pytest.fixture(autouse=True)
def _clean():
    reply_ledger._reset()
    yield
    reply_ledger._reset()


REPLY = "_INBOX_gw.BqJB7wouIJniIDngCeiy39.BqJB7wouIJniIDngCen4ei"
# Exactly what nats-py handed the callback on pop-os 2026-10-14 20:54:44.
LIVE_ERROR = 'nats: permissions violation for publish to "_inbox_gw.bqjb7wouijniidngceiy39.bqjb7wouijniidngcen4ei"'


def test_the_live_error_maps_back_to_the_request():
    reply_ledger.received(REPLY, "worker.rag.query")
    lost = reply_ledger.refused_reply(LIVE_ERROR)
    assert lost is not None
    assert lost["request_subject"] == "worker.rag.query"
    assert lost["held_s"] >= 0
    # Consumed: the same violation is not reported twice.
    assert reply_ledger.refused_reply(LIVE_ERROR) is None


def test_other_errors_and_unowed_subjects_are_not_claimed():
    reply_ledger.received(REPLY, "worker.rag.query")
    assert reply_ledger.refused_reply("nats: stale connection") is None
    assert reply_ledger.refused_reply('nats: permissions violation for publish to "tasks.x"') is None


def test_no_reply_subject_is_not_recorded():
    reply_ledger.received(None, "worker.events")
    reply_ledger.received("", "worker.events")
    assert not reply_ledger._owed


def test_the_ledger_is_bounded():
    for i in range(reply_ledger.MAX_ENTRIES + 10):
        reply_ledger.received(f"_INBOX_gw.x.{i}", "worker.rag.query")
    assert len(reply_ledger._owed) == reply_ledger.MAX_ENTRIES
    # Oldest dropped, newest kept.
    assert "_inbox_gw.x.0" not in reply_ledger._owed
    assert f"_inbox_gw.x.{reply_ledger.MAX_ENTRIES + 9}" in reply_ledger._owed


async def test_error_callback_logs_reply_undeliverable(monkeypatch):
    events = []

    class _Log:
        def error(self, event, **kw):
            events.append((event, kw))

    monkeypatch.setattr("noomesh.cluster.messaging.logger", _Log())
    m = ClusterMessaging.__new__(ClusterMessaging)
    m.nats_url = "tls://nats:4222"

    reply_ledger.received(REPLY, "worker.rag.query")
    await m._on_error(Exception(LIVE_ERROR))
    await m._on_error(Exception("nats: stale connection"))

    assert [e for e, _ in events] == ["worker.reply_undeliverable", "nats_async_error"]
    assert events[0][1]["request_subject"] == "worker.rag.query"
    assert "reload" in events[0][1]["message"]


async def test_the_worker_records_the_reply_it_owes(monkeypatch):
    from noomesh.gateway import worker_pool

    class _Msg:
        subject = "worker.rag.query"
        reply = REPLY
        data = b"not json"
        headers = None

        async def respond(self, _data):
            pass

    await worker_pool._handle_request(_Msg())
    assert reply_ledger.refused_reply(LIVE_ERROR)["request_subject"] == "worker.rag.query"
