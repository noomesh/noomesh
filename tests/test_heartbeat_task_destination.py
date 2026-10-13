# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A heartbeat task created through an MCP door can name where its result goes.

`POST /api/heartbeat/tasks` has always read `channels` and `recipients`
(routes/intelligence.rs reads both from the body), but the tool definition
never offered them. So every task created through a door was born with no
destination: it ran on schedule, produced its report, and delivered to nobody.
`noo heartbeat add --channel/--recipient` could express this; the door could
not.
"""
from __future__ import annotations

from noomesh.mcp.tool_defs.heartbeat import PaiHeartbeatCreateTask


def _task(**kw):
    base = dict(name="Weekly research", action="research_report", schedule="0 9 * * 1")
    base.update(kw)
    return PaiHeartbeatCreateTask(**base)


def test_a_destination_reaches_the_request_body():
    body = _task(channels=["google_chat"], recipients=["spaces/EXAMPLEID"]).get_body()
    assert body["channels"] == ["google_chat"]
    assert body["recipients"] == ["spaces/EXAMPLEID"]


def test_omitting_a_destination_sends_neither_key():
    """A maintenance task has nothing to tell anyone; it must not be forced
    to invent a destination, and the route defaults both to []."""
    body = _task().get_body()
    assert "channels" not in body
    assert "recipients" not in body


def test_several_channels_stay_positional():
    body = _task(
        channels=["google_chat", "telegram"],
        recipients=["spaces/EXAMPLEID", "-1001234"],
    ).get_body()
    assert body["channels"][1] == "telegram"
    assert body["recipients"][1] == "-1001234"


def test_the_manifest_exposes_the_fields():
    """The Rust doors dispatch from the generated schema, so the fields have
    to exist there, not only on the Python class."""
    props = PaiHeartbeatCreateTask.model_json_schema()["properties"]
    assert "channels" in props
    assert "recipients" in props
